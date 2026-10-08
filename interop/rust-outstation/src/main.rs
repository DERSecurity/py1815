//! An independent outstation built on the `dnp3` crate, for testing the py1815 master.
//!
//! The `dnp3` crate is a Rust DNP3 stack by Step Function I/O that this project
//! did not write. The py1815 master reads and commands this outstation in the
//! interoperability job (`interop/master_check.py`). Agreement with it is
//! evidence about the master, because the two share no code.
//!
//! The points served and the control rules are the fixture below.
//! `interop/master_check.py` and `interop/opendnp3_outstation.py` carry the
//! same fixture.
//!
//! Every control and time write received is printed, one line each, in the
//! format `master_check.py` reads from this process's log:
//!
//! ```text
//! control select bo 0 latch_on
//! control operate ao 1 250
//! time written 1700000000000
//! ```
//!
//! Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.

use std::io::Write;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnp3::app::control::{
    CommandStatus, ControlCode, Group12Var1, Group41Var1, Group41Var2, Group41Var3, Group41Var4,
    OpType, TripCloseCode,
};
use dnp3::app::measurement::{
    AnalogInput, AnalogOutputStatus, BinaryInput, BinaryOutputStatus, Counter, Flags, Time,
};
use dnp3::app::{NullListener, Timestamp};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::outstation::database::{
    Add, AnalogInputConfig, AnalogOutputStatusConfig, BinaryInputConfig, BinaryOutputStatusConfig,
    CounterConfig, Database, DatabaseHandle, EventAnalogInputVariation,
    EventAnalogOutputStatusVariation, EventBinaryInputVariation, EventBinaryOutputStatusVariation,
    EventBufferConfig, EventClass, EventCounterVariation, EventMode, StaticAnalogInputVariation,
    StaticAnalogOutputStatusVariation, StaticBinaryInputVariation,
    StaticBinaryOutputStatusVariation, StaticCounterVariation, Update, UpdateOptions,
};
use dnp3::outstation::{
    ApplicationIin, ControlHandler, ControlSupport, OperateType, OutstationApplication,
    OutstationConfig, OutstationInformation, RequestError,
};
use dnp3::tcp::{AddressFilter, Server};

// ---- The fixture. Must match interop/master_check.py and interop/opendnp3_outstation.py.

/// Binary inputs 0 to 4.
const BINARY_INPUTS: [bool; 5] = [true, false, true, false, true];
/// Analog inputs 0 to 4, served as 32-bit integers.
const ANALOG_INPUTS: [f64; 5] = [10.0, -20.0, 30.0, 40.0, 50.0];
/// The analog input served offline, with COMM_LOST set.
const ANALOG_OFFLINE_INDEX: u16 = 3;
/// Analog inputs 5 and up hold their own index, to make the integrity poll
/// larger than one fragment.
const ANALOG_COUNT: u16 = 600;
/// Counters 0 and 1.
const COUNTERS: [u32; 2] = [100, 200];
/// Binary and analog outputs 0 to 2 exist. Any other index is NOT_SUPPORTED.
const OUTPUT_COUNT: u16 = 3;
/// Analog output 2 refuses a value above the limit with OUT_OF_RANGE.
const ANALOG_OUTPUT_LIMIT_INDEX: u16 = 2;
const ANALOG_OUTPUT_LIMIT: f64 = 1000.0;
/// An operate on binary output 0 is mirrored to this binary input, and an
/// operate on analog output 0 to this analog input, so each raises an event.
const MIRROR_BINARY_INPUT: u16 = 1;
const MIRROR_ANALOG_INPUT: u16 = 1;

/// Print one line and flush, so the log is complete if the job is cancelled.
fn say(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

fn now() -> Time {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Time::synchronized(since_epoch.as_millis() as u64)
}

/// Asks for the time until a master writes it, and records the write.
struct Application {
    need_time: bool,
}

impl OutstationApplication for Application {
    fn write_absolute_time(&mut self, time: Timestamp) -> Result<(), RequestError> {
        say(&format!("time written {}", time.raw_value()));
        self.need_time = false;
        Ok(())
    }

    fn get_application_iin(&self) -> ApplicationIin {
        ApplicationIin {
            need_time: self.need_time,
            ..Default::default()
        }
    }
}

struct Information;

impl OutstationInformation for Information {}

/// The name of a binary output operation and the state it leaves the output in,
/// or None for an operation the fixture does not support.
fn operation(code: ControlCode) -> Option<(&'static str, bool)> {
    match (code.tcc, code.op_type) {
        (TripCloseCode::Nul, OpType::LatchOn) => Some(("latch_on", true)),
        (TripCloseCode::Nul, OpType::LatchOff) => Some(("latch_off", false)),
        (TripCloseCode::Nul, OpType::PulseOn) => Some(("pulse_on", true)),
        (TripCloseCode::Nul, OpType::PulseOff) => Some(("pulse_off", false)),
        (TripCloseCode::Close, OpType::PulseOn) => Some(("close", true)),
        (TripCloseCode::Trip, OpType::PulseOn) => Some(("trip", false)),
        _ => None,
    }
}

/// Applies the fixture's control rules and logs every control received.
struct Controls;

impl Controls {
    fn binary_status(control: Group12Var1, index: u16) -> CommandStatus {
        if index >= OUTPUT_COUNT || operation(control.code).is_none() {
            CommandStatus::NotSupported
        } else {
            CommandStatus::Success
        }
    }

    fn analog_status(value: f64, index: u16) -> CommandStatus {
        if index >= OUTPUT_COUNT {
            CommandStatus::NotSupported
        } else if index == ANALOG_OUTPUT_LIMIT_INDEX && value > ANALOG_OUTPUT_LIMIT {
            CommandStatus::OutOfRange
        } else {
            CommandStatus::Success
        }
    }

    fn select_analog(value: f64, index: u16) -> CommandStatus {
        say(&format!("control select ao {index} {value}"));
        Self::analog_status(value, index)
    }

    fn operate_analog(value: f64, index: u16, database: &mut DatabaseHandle) -> CommandStatus {
        say(&format!("control operate ao {index} {value}"));
        let status = Self::analog_status(value, index);
        if status == CommandStatus::Success {
            database.transaction(|db| {
                db.update(
                    index,
                    &AnalogOutputStatus::new(value, Flags::ONLINE, now()),
                    UpdateOptions::no_event(),
                );
                if index == 0 {
                    db.update(
                        MIRROR_ANALOG_INPUT,
                        &AnalogInput::new(value, Flags::ONLINE, now()),
                        UpdateOptions::new(true, EventMode::Force),
                    );
                }
            });
        }
        status
    }
}

impl ControlHandler for Controls {}

impl ControlSupport<Group12Var1> for Controls {
    fn select(
        &mut self,
        control: Group12Var1,
        index: u16,
        _database: &mut DatabaseHandle,
    ) -> CommandStatus {
        let name = operation(control.code).map_or("other", |(name, _)| name);
        say(&format!("control select bo {index} {name}"));
        Self::binary_status(control, index)
    }

    fn operate(
        &mut self,
        control: Group12Var1,
        index: u16,
        _op_type: OperateType,
        database: &mut DatabaseHandle,
    ) -> CommandStatus {
        let name = operation(control.code).map_or("other", |(name, _)| name);
        say(&format!("control operate bo {index} {name}"));
        let status = Self::binary_status(control, index);
        if let (CommandStatus::Success, Some((_, on))) = (status, operation(control.code)) {
            database.transaction(|db| {
                db.update(
                    index,
                    &BinaryOutputStatus::new(on, Flags::ONLINE, now()),
                    UpdateOptions::no_event(),
                );
                if index == 0 {
                    db.update(
                        MIRROR_BINARY_INPUT,
                        &BinaryInput::new(on, Flags::ONLINE, now()),
                        UpdateOptions::new(true, EventMode::Force),
                    );
                }
            });
        }
        status
    }
}

/// The four analog output variations differ only in the type of the value.
macro_rules! analog_output {
    ($variation:ty) => {
        impl ControlSupport<$variation> for Controls {
            fn select(
                &mut self,
                control: $variation,
                index: u16,
                _database: &mut DatabaseHandle,
            ) -> CommandStatus {
                Self::select_analog(f64::from(control.value), index)
            }

            fn operate(
                &mut self,
                control: $variation,
                index: u16,
                _op_type: OperateType,
                database: &mut DatabaseHandle,
            ) -> CommandStatus {
                Self::operate_analog(f64::from(control.value), index, database)
            }
        }
    };
}

analog_output!(Group41Var1);
analog_output!(Group41Var2);
analog_output!(Group41Var3);
analog_output!(Group41Var4);

/// Define every point of the fixture and set its value, without raising events.
fn load(db: &mut Database) {
    let quiet = UpdateOptions::no_event();
    for (index, value) in (0u16..).zip(BINARY_INPUTS) {
        db.add(
            index,
            Some(EventClass::Class1),
            BinaryInputConfig::new(
                StaticBinaryInputVariation::Group1Var2,
                EventBinaryInputVariation::Group2Var1,
            ),
        );
        db.update(index, &BinaryInput::new(value, Flags::ONLINE, now()), quiet);
    }
    for index in 0..ANALOG_COUNT {
        db.add(
            index,
            Some(EventClass::Class2),
            AnalogInputConfig::new(
                StaticAnalogInputVariation::Group30Var1,
                EventAnalogInputVariation::Group32Var1,
                0.0,
            ),
        );
        let value = ANALOG_INPUTS
            .get(usize::from(index))
            .copied()
            .unwrap_or(f64::from(index));
        let flags = if index == ANALOG_OFFLINE_INDEX {
            Flags::COMM_LOST
        } else {
            Flags::ONLINE
        };
        db.update(index, &AnalogInput::new(value, flags, now()), quiet);
    }
    for (index, value) in (0u16..).zip(COUNTERS) {
        db.add(
            index,
            Some(EventClass::Class3),
            CounterConfig::new(
                StaticCounterVariation::Group20Var1,
                EventCounterVariation::Group22Var1,
                0,
            ),
        );
        db.update(index, &Counter::new(value, Flags::ONLINE, now()), quiet);
    }
    for index in 0..OUTPUT_COUNT {
        db.add(
            index,
            None,
            BinaryOutputStatusConfig::new(
                StaticBinaryOutputStatusVariation::Group10Var2,
                EventBinaryOutputStatusVariation::Group11Var1,
            ),
        );
        db.update(
            index,
            &BinaryOutputStatus::new(false, Flags::ONLINE, now()),
            quiet,
        );
        db.add(
            index,
            None,
            AnalogOutputStatusConfig::new(
                StaticAnalogOutputStatusVariation::Group40Var1,
                EventAnalogOutputStatusVariation::Group42Var1,
                0.0,
            ),
        );
        db.update(
            index,
            &AnalogOutputStatus::new(0.0, Flags::ONLINE, now()),
            quiet,
        );
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:20000".to_string())
        .parse()?;

    let config = OutstationConfig::new(
        EndpointAddress::try_new(1024)?,
        EndpointAddress::try_new(1)?,
        EventBufferConfig::all_types(100),
    );

    let mut server = Server::new_tcp_server(LinkErrorMode::Close, endpoint);
    let outstation = server.add_outstation(
        config,
        Box::new(Application { need_time: true }),
        Box::new(Information),
        Box::new(Controls),
        NullListener::create(),
        AddressFilter::Any,
    )?;
    outstation.transaction(load);

    // Kept until the process ends: dropping the handle shuts the server down.
    let _server = server.bind().await?;
    say(&format!("outstation listening on {endpoint}"));

    std::future::pending::<()>().await;
    Ok(())
}
