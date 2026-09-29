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

use dnp3::app::control::{CommandStatus, ControlCode, Group12Var1, OpType};
use dnp3::app::measurement::{AnalogInput, BinaryInput, Counter, DoubleBitBinaryInput};
use dnp3::app::{ConnectStrategy, MaybeAsync, NullListener, ResponseHeader, Variation};
use dnp3::decode::{AppDecodeLevel, DecodeLevel};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::master::TaskError;
use dnp3::master::{
    AssociationConfig, AssociationHandler, AssociationInformation, Classes, CommandBuilder,
    CommandError, CommandMode, CommandResponseError, CommandSupport, EventClasses, HeaderInfo,
    MasterChannelConfig, ReadHandler, ReadRequest, ReadType,
};
use dnp3::tcp::{spawn_master_tcp_client, EndpointList};

/// What the fixture serves. Must match `interop/outstation.py`.
const EXPECTED: [i32; 5] = [10, -20, 30, 40, 50];

/// A binary output the fixture operates.
const CONTROLLABLE_INDEX: u8 = 0;

/// One it deliberately does not, so a refusal can be seen arriving as a status
/// against that point while the rest of the request succeeds.
const UNCONTROLLABLE_INDEX: u8 = 9;

/// The index the fixture serves offline, with COMM_LOST set.
const OFFLINE_INDEX: u16 = 3;

/// One event as it arrived, with everything about it that is worth checking.
///
/// Both object types in one ordered list rather than an index per type in two.
/// Separate lists record neither the order the types arrived in nor what the
/// events carried, so a response with its binary header in front of the analog
/// ones -- or a binary at the right index carrying the wrong value or
/// variation -- collects identically to a correct one and passes.
#[derive(Debug)]
enum Arrived {
    Analog(u16, f64, Variation),
    Binary(u16, bool, Variation),
}

impl Arrived {
    fn matches(&self, wanted: &Arrived) -> bool {
        match (self, wanted) {
            (Arrived::Analog(i, v, var), Arrived::Analog(j, w, wvar)) => {
                i == j && (v - w).abs() <= f64::EPSILON && var == wvar
            }
            (Arrived::Binary(i, v, var), Arrived::Binary(j, w, wvar)) => {
                i == j && v == w && var == wvar
            }
            _ => false,
        }
    }
}

/// The events the fixture holds, per class and in order. Must match
/// `interop/outstation.py`.
///
/// The values are unlike anything `EXPECTED` holds and unlike each other's
/// class, so a value here cannot have come from the point map nor from a class
/// other than the one that returned it. The binary event sits behind the
/// analog ones of its class, which is the order the points changed -- an
/// outstation that gathered its events by type would tell a master a different
/// story about when things happened, and that is what this sequence catches.
fn expected(class: u8) -> Vec<Arrived> {
    match class {
        1 => vec![
            Arrived::Analog(0, 101.0, Variation::Group32Var3),
            Arrived::Analog(1, 102.0, Variation::Group32Var3),
            Arrived::Binary(BINARY_EVENT_INDEX, true, Variation::Group2Var2),
        ],
        2 => vec![Arrived::Analog(2, 203.0, Variation::Group32Var3)],
        _ => vec![Arrived::Analog(3, 304.0, Variation::Group32Var3)],
    }
}

/// The index of the binary event the fixture seeds in class 1, behind the
/// analog ones. It is the assertion that the order of a class read is the
/// order the points changed rather than one gathered by type.
const BINARY_EVENT_INDEX: u16 = 0;

/// The whole quality octet each point is expected to carry, which is what the
/// fixture sets: ONLINE alone, or COMM_LOST alone with ONLINE cleared.
const FLAGS_ONLINE: u8 = 0x01;
const FLAGS_OFFLINE: u8 = 0x04;

/// Everything the read handler collected, shared with the main task.
#[derive(Default)]
struct Readings {
    analog: HashMap<u16, (f64, u8)>,
    variations: Vec<Variation>,
    fragments: usize,
    restart_seen: bool,
    /// Set by the main task between the two reads. Events and static values
    /// arrive through the same handler, so without being told which it is
    /// looking at the collector would have the class read's values overwrite
    /// the point map's -- and the assertions about the point map would then be
    /// checking events against static expectations.
    collecting_events: bool,
    /// Every event of every class read, in the order it arrived and with both
    /// object types in the one list, so the sequence itself can be checked.
    events: Vec<Arrived>,
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
        info: HeaderInfo,
        iter: &mut dyn Iterator<Item = (AnalogInput, u16)>,
    ) {
        let mut readings = self.0.lock().unwrap();
        if readings.collecting_events {
            // Kept in arrival order rather than by index: an event is a thing
            // that happened, and two of them may carry the same index.
            let variation = info.variation;
            for (value, index) in iter {
                readings
                    .events
                    .push(Arrived::Analog(index, value.value, variation));
            }
            return;
        }
        // The read names a variation, so the variation that comes back is part
        // of what is being checked. Without this a g30v2 answer to a g30v1
        // request would land in this same handler and pass.
        readings.variations.push(info.variation);
        for (value, index) in iter {
            readings
                .analog
                .insert(index, (value.value, value.flags.value));
        }
    }

    fn handle_binary_input(
        &mut self,
        info: HeaderInfo,
        iter: &mut dyn Iterator<Item = (BinaryInput, u16)>,
    ) {
        let mut readings = self.0.lock().unwrap();
        if !readings.collecting_events {
            // The fixture serves no static binary inputs, so anything here
            // outside a class read is not something this job asked for.
            return;
        }
        let variation = info.variation;
        for (value, index) in iter {
            readings
                .events
                .push(Arrived::Binary(index, value.value, variation));
        }
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

    // No unsolicited handling, and no startup class scan beyond class 0. This
    // outstation sends no unsolicited responses: it agrees to DISABLE, having
    // nothing to stop, and refuses ENABLE, which asks for something it does not
    // do. A startup sequence that argued with it about either would be testing
    // that exchange rather than the read, and both answers are covered by the
    // function code sweep.
    //
    // The event classes are read further down, explicitly and one at a time.
    // Leaving them out of the startup scan is what makes that possible: the
    // point map is asserted against a read that carried nothing else, and each
    // class against a read that named it alone.
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

    // -- the events ---------------------------------------------------------
    //
    // A second read rather than a startup class scan, so the assertions about
    // the point map above are made against the point map alone. The collector
    // is told that what follows is events rather than left to infer it, which
    // needs no more of the crate's API than the reads themselves.
    //
    // Three reads rather than one integrity poll, so that a class answered with
    // another class's events is a failure here rather than something this job
    // sees as the right values under the wrong heading.
    readings.lock().unwrap().collecting_events = true;

    for (class, variation) in [
        (1u8, Variation::Group60Var2),
        (2, Variation::Group60Var3),
        (3, Variation::Group60Var4),
    ] {
        let before = readings.lock().unwrap().events.len();

        let events = tokio::time::timeout(
            Duration::from_secs(30),
            association.read(ReadRequest::all_objects(variation)),
        )
        .await;

        match events {
            Err(_) => fail(&format!("no answer to a class {class} read within 30s")),
            Ok(Err(error)) => fail(&format!("the class {class} read failed: {error}")),
            Ok(Ok(())) => (),
        }

        // Checked here rather than at the end, against what *this* read
        // returned. Comparing the three classes together at the end would pass
        // an outstation that answered class 1 with every event and the other
        // two with nothing.
        let readings = readings.lock().unwrap();
        let arrived = &readings.events[before..];
        let wanted = expected(class);
        if arrived.len() != wanted.len() {
            fail(&format!(
                "class {class} returned {} events, expected {}: {arrived:?}",
                arrived.len(),
                wanted.len()
            ));
        }
        for (position, (got, want)) in arrived.iter().zip(wanted.iter()).enumerate() {
            if !got.matches(want) {
                fail(&format!(
                    "class {class} event {position} was {got:?}, expected {want:?}"
                ));
            }
        }
        println!(
            "rust-master: class {class} read completed, {} events in order",
            arrived.len()
        );
    }

    // Two assertions where there was one, because they sit at different layers
    // and neither stands in for the other. An unsupported *point* comes back as
    // a status against that object; an unsupported *function* comes back as an
    // indication against the fragment. Checking only the first would retire the
    // D9 coverage while appearing to keep it.

    // A point the outstation owns.
    let accepted = tokio::time::timeout(
        Duration::from_secs(30),
        association.operate(
            CommandMode::DirectOperate,
            CommandBuilder::single_header_u8(
                Group12Var1::from_code(ControlCode::from_op_type(OpType::LatchOn)),
                CONTROLLABLE_INDEX,
            ),
        ),
    )
    .await;

    match accepted {
        Err(_) => fail("the outstation did not answer a control within 30s"),
        Ok(Err(error)) => fail(&format!(
            "a control the outstation owns was refused: {error}"
        )),
        Ok(Ok(())) => println!("rust-master: the control was accepted"),
    }

    // A point it does not. The refusal has to arrive as a per-object status
    // rather than as an indication against the fragment, which is what D14
    // promises and what a master driving one point at a time can prove.
    //
    // This library checks the echo on the way past: a response whose objects
    // differ from the request is ObjectValueMismatch, and one whose header
    // count differs is HeaderCountMismatch. Either would surface here as a
    // failure that is not BadStatus.
    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        association.operate(
            CommandMode::DirectOperate,
            CommandBuilder::single_header_u8(
                Group12Var1::from_code(ControlCode::from_op_type(OpType::LatchOn)),
                UNCONTROLLABLE_INDEX,
            ),
        ),
    )
    .await;

    match refused {
        Err(_) => fail("the outstation did not answer a control within 30s"),
        Ok(Ok(())) => fail("a point the outstation does not control was accepted"),
        Ok(Err(CommandError::Response(CommandResponseError::BadStatus(status)))) => {
            if status != CommandStatus::NotSupported {
                fail(&format!(
                    "the point was refused, but with {status:?} rather than NotSupported"
                ));
            }
            println!("rust-master: the uncontrolled point was refused per object, as it should be");
        }
        Ok(Err(other)) => fail(&format!(
            "the refusal did not arrive as a per-object status: {other}"
        )),
    }

    // A function this outstation still does not implement. The half of D9 that
    // a sweep checking indication bits on our own socket cannot show: that a
    // refusal reaches an independent master as a refusal rather than as a
    // timeout.
    let restart = tokio::time::timeout(Duration::from_secs(30), association.cold_restart()).await;

    match restart {
        Err(_) => fail("the outstation did not answer a cold restart within 30s"),
        Ok(Ok(_)) => fail("the outstation accepted a cold restart; it implements none"),
        Ok(Err(TaskError::RejectedByIin2(iin))) => {
            if !iin.iin2.get_no_func_code_support() {
                fail(&format!(
                    "the function was rejected, but not with FUNC_NOT_SUPPORTED; iin2 was {:?}",
                    iin.iin2
                ));
            }
            println!(
                "rust-master: the unsupported function was refused with FUNC_NOT_SUPPORTED, as it should be"
            );
        }
        Ok(Err(other)) => fail(&format!(
            "the function failed without being refused in band: {other}"
        )),
    }

    // -- verdict ------------------------------------------------------------
    let readings = readings.lock().unwrap();
    if readings.fragments == 0 {
        fail("the outstation returned no response fragments");
    }
    println!(
        "rust-master: {} fragments, {} analog inputs, variations {:?}",
        readings.fragments,
        readings.analog.len(),
        readings.variations
    );

    if readings.variations.is_empty() {
        fail("no analog header arrived, so the variation was never checked");
    }
    if let Some(other) = readings
        .variations
        .iter()
        .find(|variation| **variation != Variation::Group30Var1)
    {
        fail(&format!("asked for g30v1 and a header carried {other:?}"));
    }

    for (index, expected) in EXPECTED.iter().enumerate() {
        let index = index as u16;
        let Some((value, flags)) = readings.analog.get(&index) else {
            fail(&format!("index {index} missing from the response"));
        };
        if (*value - f64::from(*expected)).abs() > f64::EPSILON {
            fail(&format!("index {index} read {value}, expected {expected}"));
        }

        // The assertion the opendnp3-driven job cannot make. The whole octet is
        // compared rather than the two bits of interest: the fixture sets
        // exactly one value per point, so a subset check would pass a point
        // that was also, say, over-range, and this peer exists precisely to
        // see what the other one cannot.
        let wanted = if index == OFFLINE_INDEX {
            FLAGS_OFFLINE
        } else {
            FLAGS_ONLINE
        };
        if *flags != wanted {
            fail(&format!(
                "index {index} quality octet was {flags:#04x}, expected {wanted:#04x}"
            ));
        }
    }

    // -- the events ---------------------------------------------------------
    //
    // The part of this outstation no independent master had read until now.
    // Each class was checked as it arrived, against its own events, in order,
    // with their values and variations -- so what is left for the end is the
    // total, which catches three reads that between them returned nothing
    // without any one of them noticing its own emptiness.
    let seen = readings.events.len();
    let wanted: usize = (1..=3).map(|class| expected(class).len()).sum();
    if seen != wanted {
        fail(&format!(
            "read {seen} events across the classes, expected {wanted}"
        ));
    }

    println!(
        "rust-master: OK, {} analog inputs match with their quality octet, and {seen} events \
         came back from the buffers",
        EXPECTED.len()
    );
    Ok(())
}
