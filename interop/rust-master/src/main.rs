//! An independently developed master, in a different language, reading this outstation.
//!
//! The other master this repository drives is built on opendnp3, a C++ stack
//! that has been end-of-life since 2022. This one is a Rust implementation
//! written by different people from the same specification, which makes it a
//! second opinion rather than a second interface onto the first.
//!
//! It also closes a gap the other one structurally cannot. opendnp3's Python
//! bindings store point values as bare scalars and discard the quality octet,
//! so the job driving them checks values and not flags. This stack hands the
//! flags to the read handler, so the point this outstation deliberately serves
//! offline is verified here as offline rather than merely as a number.
//!
//! Exits non-zero, loudly, on anything it cannot verify.
//!
//! Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnp3::app::control::{ControlCode, Group12Var1, OpType};
use dnp3::app::measurement::{AnalogInput, BinaryInput, Counter, DoubleBitBinaryInput};
use dnp3::app::{ConnectStrategy, MaybeAsync, NullListener, ResponseHeader, Variation};
use dnp3::decode::{AppDecodeLevel, DecodeLevel};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::master::{
    AssociationConfig, AssociationHandler, AssociationInformation, Classes, CommandBuilder,
    CommandMode, CommandSupport, EventClasses, HeaderInfo, MasterChannelConfig, ReadHandler,
    ReadRequest, ReadType,
};
use dnp3::tcp::{spawn_master_tcp_client, EndpointList};

/// What the fixture serves. Must match `interop/outstation.py`.
const EXPECTED: [i32; 5] = [10, -20, 30, 40, 50];

/// The index the fixture serves offline, with COMM_LOST set.
const OFFLINE_INDEX: u16 = 3;

/// DNP3 quality bits, which this stack exposes as the raw octet.
const FLAG_ONLINE: u8 = 0x01;
const FLAG_COMM_LOST: u8 = 0x04;

/// Everything the read handler collected, shared with the main task.
#[derive(Default)]
struct Readings {
    analog: HashMap<u16, (f64, u8)>,
    fragments: usize,
    restart_seen: bool,
}

#[derive(Clone)]
struct Collector(Arc<Mutex<Readings>>);

impl ReadHandler for Collector {
    fn begin_fragment(&mut self, _read_type: ReadType, header: ResponseHeader) -> MaybeAsync<()> {
        let mut readings = self.0.lock().unwrap();
        readings.fragments += 1;
        if header.iin.iin1.get_device_restart() {
            readings.restart_seen = true;
        }
        MaybeAsync::ready(())
    }

    fn end_fragment(&mut self, _read_type: ReadType, _header: ResponseHeader) -> MaybeAsync<()> {
        MaybeAsync::ready(())
    }

    fn handle_analog_input(
        &mut self,
        _info: HeaderInfo,
        iter: &mut dyn Iterator<Item = (AnalogInput, u16)>,
    ) {
        let mut readings = self.0.lock().unwrap();
        for (value, index) in iter {
            readings.analog.insert(index, (value.value, value.flags.value));
        }
    }

    fn handle_binary_input(
        &mut self,
        _info: HeaderInfo,
        _iter: &mut dyn Iterator<Item = (BinaryInput, u16)>,
    ) {
    }

    fn handle_double_bit_binary_input(
        &mut self,
        _info: HeaderInfo,
        _iter: &mut dyn Iterator<Item = (DoubleBitBinaryInput, u16)>,
    ) {
    }

    fn handle_counter(
        &mut self,
        _info: HeaderInfo,
        _iter: &mut dyn Iterator<Item = (Counter, u16)>,
    ) {
    }
}

struct Handler;
impl AssociationHandler for Handler {}

struct Information;
impl AssociationInformation for Information {}

fn fail(message: &str) -> ! {
    eprintln!("rust-master: FAIL {message}");
    std::process::exit(1);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:20000".to_string());

    let master_address = EndpointAddress::try_new(1)?;
    let outstation_address = EndpointAddress::try_new(1024)?;

    let mut config = MasterChannelConfig::new(master_address);
    config.decode_level = DecodeLevel::from(AppDecodeLevel::ObjectValues);

    let mut channel = spawn_master_tcp_client(
        LinkErrorMode::Close,
        config,
        EndpointList::new(endpoint.clone(), &[]),
        ConnectStrategy::default(),
        NullListener::create(),
    );

    // No unsolicited handling and no startup class scan beyond class 0. This
    // outstation serves static data and refuses the unsolicited functions, and
    // a startup sequence that argued with it about that would be testing the
    // refusal rather than the read. The refusal itself is covered by the
    // function code sweep.
    let mut association_config = AssociationConfig::new(
        EventClasses::none(),
        EventClasses::none(),
        Classes::class0(),
        EventClasses::none(),
    );
    association_config.auto_time_sync = None;
    association_config.keep_alive_timeout = None;

    let readings = Arc::new(Mutex::new(Readings::default()));
    let collector = Collector(readings.clone());

    let mut association = channel
        .add_association(
            outstation_address,
            association_config,
            Box::new(collector),
            Box::new(Handler),
            Box::new(Information),
        )
        .await?;

    channel.enable().await?;

    // An explicit read of the variation this outstation serves. The integrity
    // poll would do as well, but naming the variation means an outstation that
    // answered a specific request with a different one is a failure here rather
    // than something the master quietly accommodated.
    let read = tokio::time::timeout(
        Duration::from_secs(30),
        association.read(ReadRequest::one_byte_range(Variation::Group30Var1, 0, 4)),
    )
    .await;

    match read {
        Err(_) => fail(&format!("no response from {endpoint} within 30s")),
        Ok(Err(error)) => fail(&format!("the read failed: {error}")),
        Ok(Ok(())) => println!("rust-master: read completed"),
    }

    // A control this outstation must refuse. Proving the refusal reaches a
    // master as a refusal, rather than as a timeout, is the half of D9 that a
    // sweep checking indication bits on our own socket cannot show.
    let control = tokio::time::timeout(
        Duration::from_secs(30),
        association.operate(
            CommandMode::DirectOperate,
            CommandBuilder::single_header_u8(
                Group12Var1::from_code(ControlCode::from_op_type(OpType::LatchOn)),
                0u8,
            ),
        ),
    )
    .await;

    match control {
        Err(_) => fail("the outstation did not answer a control request within 30s"),
        Ok(Ok(())) => fail("the outstation accepted a control; it is supposed to refuse every one"),
        Ok(Err(error)) => println!("rust-master: the control was refused, as it should be: {error}"),
    }

    // -- verdict ------------------------------------------------------------
    let readings = readings.lock().unwrap();
    if readings.fragments == 0 {
        fail("the outstation returned no response fragments");
    }
    println!(
        "rust-master: {} fragments, {} analog inputs",
        readings.fragments,
        readings.analog.len()
    );

    for (index, expected) in EXPECTED.iter().enumerate() {
        let index = index as u16;
        let Some((value, flags)) = readings.analog.get(&index) else {
            fail(&format!("index {index} missing from the response"));
        };
        if (*value - f64::from(*expected)).abs() > f64::EPSILON {
            fail(&format!("index {index} read {value}, expected {expected}"));
        }

        // The assertion the opendnp3-driven job cannot make.
        let online = flags & FLAG_ONLINE != 0;
        let comm_lost = flags & FLAG_COMM_LOST != 0;
        if index == OFFLINE_INDEX {
            if online || !comm_lost {
                fail(&format!(
                    "index {index} is served offline and should read COMM_LOST with ONLINE \
                     clear; flags were {flags:#04x}"
                ));
            }
        } else if !online || comm_lost {
            fail(&format!(
                "index {index} should read ONLINE; flags were {flags:#04x}"
            ));
        }
    }

    println!(
        "rust-master: OK, {} analog inputs match, and the quality octet with them",
        EXPECTED.len()
    );
    Ok(())
}
