// Copyright 2026 DER Security Corp. Licensed under the GNU General Public License,
// version 3 only: see LICENSE in this directory.

package py1815conformance

import io.stepfunc.dnp3c.dnp3.app._
import io.stepfunc.dnp3c.dnp3.app.objects.AttributeValue
import io.stepfunc.dnp3c.dnp3.{
  ActionResult, ActionTiming, CheckReporter, DeferredCheck, EventExpectation, InputKind, IntegrationPlugin,
  PluginReporter
}

import scala.collection.mutable

/**
 * What the plugin is told that the device does not report about itself.
 *
 * @param timeToleranceMs how far an event's time may be from when the plugin generated it, and the longest delay a
 *                        delay measurement may report. The device's Device Profile states no figure for either.
 * @param operateWaitMs   how long a check of an output allows a request to reach the device and be carried out. A
 *                        request that draws no response, such as a broadcast or a direct operate without
 *                        acknowledgment, gives the harness nothing to wait for before it asks.
 */
final case class PluginSettings(command: FixtureCommand, timeToleranceMs: Long = 100, operateWaitMs: Long = 1000)

/** A step the outstation cannot perform, because it does not have the feature the step is for. */
final class NotSupported(feature: String)
    extends Exception(
      s"The py1815 Level 2 outstation has no $feature. A procedure that needs it is turned off with its supports.* " +
        "option in device.ini, with the reason in README.md.")

/**
 * Performs on the py1815 outstation the steps the harness cannot perform over DNP3, and checks what the harness
 * received against what the device itself holds.
 *
 * Every method acts or checks through the device's control channel, at once except for a check of an output, which
 * allows a request operateWaitMs to arrive. None prompts: this implements
 * IntegrationPlugin directly, so there is no default that waits on standard input. A step for a feature the
 * outstation does not have throws.
 */
final class Py1815Plugin(settings: PluginSettings) extends IntegrationPlugin {

  // One input change the device answered with an event for.
  private final case class Generated(kind: String, index: Int, value: Double, timeMs: Long, eventClass: Int) {
    var checked = false
    override def toString: String = s"$kind$index = ${show(kind, value)} at $timeMs (class $eventClass)"
  }

  // One write that reached an output, as the device recorded it.
  private final case class Operation(number: Long, kind: String, index: Int, value: String)

  // The event generateTimeEvent made, and the plugin's own clock just before and just after it was made.
  private final case class TimeEvent(event: Generated, before: Long, after: Long)

  private var fixture: Option[Fixture] = None
  // The events generated since the device last powered on, a batch for each generation.
  private val batches = mutable.ListBuffer[List[Generated]]()
  private var lastOperation = 0L
  private val unchecked = mutable.ListBuffer[Operation]()
  private var recordedCounters: Option[Map[Int, Long]] = None
  private var timeEvent: Option[TimeEvent] = None
  private var patterns = 0

  Runtime.getRuntime.addShutdownHook(new Thread(() => fixture.foreach(_.kill())))

  // ==============
  // Meta callbacks
  // ==============

  override def startProcedure(reporter: PluginReporter): Unit = {
    batches.clear()
    unchecked.clear()
    lastOperation = 0
    recordedCounters = None
    timeEvent = None
    patterns = 0
    fixture = Some(new Fixture(settings.command))
    reporter.log(s"Started the outstation on port ${settings.command.port}")
  }

  override def endProcedure(reporter: PluginReporter): Unit = {
    val running = fixture
    fixture = None
    running.foreach { f =>
      try {
        refreshOperations(f)
        if (unchecked.nonEmpty) {
          reporter.log(s"Outputs the device operated that no step asked about: ${listed(unchecked)}")
        }
      } catch { case _: FixtureException => }
      f.close()
    }
  }

  private def device: Fixture =
    fixture.getOrElse(throw new FixtureException("The device is not running: no procedure has started it"))

  // =======
  // Actions
  // =======

  override def cyclePower(reporter: PluginReporter): Unit = {
    powerCycle(reporter, "Cycled power")
  }

  // A power cycle loses the events the device held, so the batches generated before it can no longer be reported.
  private def powerCycle(reporter: PluginReporter, what: String, changes: (String, ujson.Value)*): Unit = {
    val state = device.ask("power_cycle", "settings" -> ujson.Obj.from(changes))
    batches.clear()
    reporter.log(s"$what. The device is listening again; its settings are ${ujson.write(state("settings"))}")
  }

  override def setLinkLayerConfirm(reporter: PluginReporter, value: Boolean): Unit = {
    if (value) throw new NotSupported("data link confirmation of its own transmissions")
    reporter.log("The outstation never requests data link confirmation, so there is nothing to turn off")
  }

  override def setSelfAddressSupport(reporter: PluginReporter, value: Boolean): Unit = {
    if (value) throw new NotSupported("self-address support")
    reporter.log("The outstation has no self-address support, so there is nothing to turn off")
  }

  // --------------------------------------------------------------- controls

  override def checkBinaryOutputOperate(reporter: CheckReporter, index: Int): Option[DeferredCheck] =
    operated(reporter, "BO", index)

  override def checkBinaryOutputNotOperate(reporter: CheckReporter): Option[DeferredCheck] =
    notOperated(reporter, "BO")

  override def checkAnalogOutputOperate(reporter: CheckReporter, index: Int): Option[DeferredCheck] =
    operated(reporter, "AO", index)

  override def checkAnalogOutputNotOperate(reporter: CheckReporter): Option[DeferredCheck] =
    notOperated(reporter, "AO")

  private def refreshOperations(from: Fixture): Unit = {
    val state = from.ask("state")
    state("operated").arr.foreach { item =>
      val number = item("number").num.toLong
      if (number > lastOperation) {
        unchecked += Operation(number, item("kind").str, item("index").num.toInt, ujson.write(item("value")))
        lastOperation = number
      }
    }
  }

  // Ask the device what it has operated until wanted holds or operateWaitMs has passed, and say whether it held.
  // The harness asks about an output as soon as it has sent the request. Where the request draws no response, the
  // device may not have read it yet.
  private def awaitOperations(wanted: () => Boolean): Boolean = {
    val deadline = System.nanoTime() + settings.operateWaitMs * 1000000L
    refreshOperations(device)
    while (!wanted() && System.nanoTime() < deadline) {
      Thread.sleep(10)
      refreshOperations(device)
    }
    wanted()
  }

  // The device operated the output once since the last check of it, and that one operation is now accounted for.
  private def operated(reporter: CheckReporter, kind: String, index: Int): Option[DeferredCheck] = {
    awaitOperations(() => unchecked.exists(o => o.kind == kind && o.index == index))
    unchecked.filter(o => o.kind == kind && o.index == index).toList match {
      case one :: Nil =>
        unchecked -= one
        reporter.log(s"The device operated $kind$index once, to ${one.value}")
        None
      case Nil =>
        throw new Exception(
          s"The device did not operate $kind$index. Operations not yet accounted for: ${listed(unchecked)}")
      case several =>
        throw new Exception(s"The device operated $kind$index ${several.size} times: ${listed(several)}")
    }
  }

  // Waits the whole of operateWaitMs unless an operation shows sooner: a check made before the device has read the
  // request would find nothing whatever the device goes on to do.
  private def notOperated(reporter: CheckReporter, kind: String): Option[DeferredCheck] = {
    awaitOperations(() => unchecked.exists(_.kind == kind))
    val found = unchecked.filter(_.kind == kind).toList
    if (found.nonEmpty) throw new Exception(s"The device operated ${listed(found)}")
    reporter.log(s"The device operated no $kind since the last check, watched for ${settings.operateWaitMs} ms")
    None
  }

  private def listed(operations: Iterable[Operation]): String =
    if (operations.isEmpty) "none" else operations.map(o => s"${o.kind}${o.index} to ${o.value}").mkString(", ")

  // ------------------------------------------------------- event generation

  private def state(): ujson.Obj = device.ask("state")

  private def indices(state: ujson.Obj, name: String): List[Int] =
    state(name).obj.keys.map(_.toInt).toList.sorted

  // the inputs of a kind that report events in a class, by the device's own account
  private def inClass(state: ujson.Obj, kind: String, eventClass: Int): List[Int] =
    state("event_classes")(kind).obj
      .collect { case (index, c) if c.num.toInt == eventClass => index.toInt }
      .toList
      .sorted

  private def classOf(eventClass: EventClass): Int = eventClass match {
    case EventClass.Class1 => 1
    case EventClass.Class2 => 2
    case EventClass.Class3 => 3
    case other => throw new Exception(s"$other is not one class")
  }

  // Changes that toggle binary inputs in the order given; an input named twice goes there and back.
  private def toggles(state: ujson.Obj, which: Seq[Int]): List[(String, Int, ujson.Value)] = {
    val now = mutable.Map[Int, Boolean]()
    which.toList.map { index =>
      val next = !now.getOrElse(index, state("binary")(index.toString).bool)
      now(index) = next
      ("BI", index, ujson.Bool(next))
    }
  }

  // Changes that move analog inputs by five deadbands, so each reports an event.
  private def steps(state: ujson.Obj, which: Seq[Int]): List[(String, Int, ujson.Value)] = {
    val by = 5 * state("deadband").num
    which.toList.map(index => ("AI", index, ujson.Num(state("analog")(index.toString).num + by)))
  }

  // Analog inputs with those that have not changed since the device powered on first. The outstation keeps one
  // event for each analog input, so a second change to the same input replaces the event of the first. Changing
  // another input instead leaves the earlier event in the buffer, where a later step can ask whether it was kept.
  private def unusedFirst(analog: List[Int]): List[Int] = {
    val used = batches.flatten.collect { case e if e.kind == "AI" => e.index }.toSet
    analog.filterNot(used.contains) ++ analog.filter(used.contains)
  }

  // Changes that generate events in one class: binary inputs toggled, or analog inputs moved, whichever the class
  // holds. Each of the first `points` inputs of the class changes once.
  private def classChanges(state: ujson.Obj, eventClass: Int, points: Int): List[(String, Int, ujson.Value)] = {
    val binary = inClass(state, "BI", eventClass)
    val analog = unusedFirst(inClass(state, "AI", eventClass))
    if (binary.isEmpty && analog.isEmpty) throw new Exception(s"The device has no input in class $eventClass")
    toggles(state, binary.take(points)) ++ steps(state, analog.take(points))
  }

  // Changes that generate exactly `count` events in one class. A binary input reports every change, so one input
  // is toggled that many times. An analog input reports only its latest value, so that many inputs are moved once.
  private def exactClassChanges(state: ujson.Obj, eventClass: Int, count: Int): List[(String, Int, ujson.Value)] =
    inClass(state, "BI", eventClass).headOption match {
      case Some(index) => toggles(state, List.fill(count)(index))
      case None =>
        val analog = unusedFirst(inClass(state, "AI", eventClass))
        if (analog.size < count) {
          throw new Exception(s"Class $eventClass has ${analog.size} analog inputs, too few for $count events")
        }
        steps(state, analog.take(count))
    }

  // Make the changes, and return those the device buffered an event for.
  private def apply(reporter: PluginReporter, changes: List[(String, Int, ujson.Value)]): List[Generated] = {
    if (changes.isEmpty) throw new Exception("There is nothing to change")
    val before = state()
    val request = ujson.Arr.from(changes.map { case (kind, index, value) => ujson.Arr(kind, index, value) })
    val done = device.ask("set", "changes" -> request)("changes").arr.toList
    val generated = done.filter(_("events").num > 0).map { change =>
      val kind = change("kind").str
      val index = change("index").num.toInt
      val value = change("value") match {
        case ujson.Bool(b) => if (b) 1.0 else 0.0
        case other => other.num
      }
      val eventClass = before("event_classes")(kind)(index.toString).num.toInt
      Generated(kind, index, value, change("time_ms").num.toLong, eventClass)
    }
    if (done.size <= 12) done.foreach(change => reporter.log(s"Changed ${ujson.write(change)}"))
    else reporter.log(s"Made ${done.size} changes, from ${ujson.write(done.head)} to ${ujson.write(done.last)}")
    generated
  }

  // Make the changes as a new batch, requiring that every one of them is an event.
  private def generate(reporter: PluginReporter, changes: List[(String, Int, ujson.Value)]): List[Generated] = {
    val generated = apply(reporter, changes)
    if (generated.size != changes.size) {
      throw new Exception(s"The device buffered ${generated.size} events for ${changes.size} changes")
    }
    batches += generated
    reporter.log(s"The device buffered ${generated.size} event(s)")
    generated
  }

  override def generateInputChanges(reporter: PluginReporter, kind: InputKind[?]): Unit = kind match {
    case InputKind.BinaryInput =>
      // three inputs of the first class that has binary inputs, the first of them changing twice
      val s = state()
      val some = List(1, 2, 3).map(inClass(s, "BI", _)).find(_.nonEmpty).getOrElse(Nil).take(3)
      generate(reporter, toggles(s, some ++ some.take(1)))
    case InputKind.AnalogInput =>
      val s = state()
      generate(reporter, steps(s, unusedFirst(indices(s, "analog")).take(4)))
    case InputKind.Counter =>
      // every counter counts up; the outstation reports no counter events, so this is no batch
      val s = state()
      val changes = indices(s, "counters").map { index =>
        ("CTR", index, ujson.Num(s("counters")(index.toString).num + 3 + index))
      }
      val generated = apply(reporter, changes)
      if (generated.nonEmpty) throw new Exception(s"The device buffered counter events: ${generated.mkString(", ")}")
    case InputKind.DoubleBitInput => throw new NotSupported("double-bit binary inputs")
  }

  override def generateExactInputEvents(reporter: PluginReporter, kind: InputKind[?], numEvents: Int): Unit =
    kind match {
      case InputKind.BinaryInput =>
        val s = state()
        val index = List(1, 2, 3).flatMap(inClass(s, "BI", _)).headOption
          .getOrElse(throw new Exception("The device has no binary input that reports events"))
        generate(reporter, toggles(s, List.fill(numEvents)(index)))
      case InputKind.AnalogInput =>
        // an analog input reports only its latest value, so each event needs an input of its own
        val s = state()
        val analog = unusedFirst(indices(s, "analog"))
        if (analog.size < numEvents) {
          throw new Exception(s"The device has ${analog.size} analog inputs, too few for $numEvents events")
        }
        generate(reporter, steps(s, analog.take(numEvents)))
      case InputKind.Counter => throw new NotSupported("counter change events")
      case InputKind.DoubleBitInput => throw new NotSupported("double-bit binary inputs")
    }

  override def generateClassEvents(reporter: PluginReporter, eventClass: EventClass): Unit = {
    val s = state()
    eventClass match {
      case EventClass.All =>
        // one batch across the classes: no input is in two of them, so the three sets of changes do not overlap
        generate(reporter, List(1, 2, 3).flatMap(classChanges(s, _, 3)))
      case one => generate(reporter, classChanges(s, classOf(one), 3))
    }
  }

  override def generateExactClassEvents(reporter: PluginReporter, eventClass: EventClass, numEvents: Int): Unit =
    generate(reporter, exactClassChanges(state(), classOf(eventClass), numEvents))

  // Every binary input set to a pattern that alternates by index, and inverts each time it is asked for.
  override def generateBinaryInputPattern(reporter: PluginReporter): Unit = {
    patterns += 1
    val s = state()
    val changes = indices(s, "binary").flatMap { index =>
      val wanted = (index + patterns) % 2 == 0
      if (s("binary")(index.toString).bool == wanted) None else Some(("BI", index, ujson.Bool(wanted)))
    }
    batches += apply(reporter, changes)
  }

  override def generateDoubleBitBinaryInputPattern(reporter: PluginReporter): Unit =
    throw new NotSupported("double-bit binary inputs")

  // Every analog input set to a value of its own, further from its last one than the deadband.
  override def generateAnalogInputPattern(reporter: PluginReporter): Unit = {
    patterns += 1
    val s = state()
    val changes = indices(s, "analog").map(index => ("AI", index, ujson.Num(1000 * patterns + 37 * index)))
    batches += apply(reporter, changes)
  }

  // -------------------------------------------------- uninstalling points

  override def uninstallBinaryInputs(reporter: PluginReporter): Unit =
    powerCycle(reporter, "Uninstalled every binary input", "binary_inputs" -> false)

  override def uninstallDoubleBitBinaryInputs(reporter: PluginReporter): Unit =
    throw new NotSupported("double-bit binary inputs")

  // the frozen counters go with the counters they freeze
  override def uninstallCounters(reporter: PluginReporter): Unit =
    powerCycle(reporter, "Uninstalled every counter", "counters" -> false)

  override def uninstallBinaryOutputs(reporter: PluginReporter): Unit =
    powerCycle(reporter, "Uninstalled every binary output", "binary_outputs" -> false)

  override def uninstallAnalogOutputs(reporter: PluginReporter): Unit =
    powerCycle(reporter, "Uninstalled every analog output", "analog_outputs" -> false)

  override def reinstallPoints(reporter: PluginReporter): Unit =
    powerCycle(
      reporter,
      "Reinstalled every point",
      "binary_inputs" -> true,
      "analog_inputs" -> true,
      "counters" -> true,
      "binary_outputs" -> true,
      "analog_outputs" -> true)

  // -------------------------------------------- remote supervisory control

  override def enableRemoteSupervisoryControl(reporter: PluginReporter): Unit =
    throw new NotSupported("local state for its outputs")

  override def setGlobalRemoteSupervisoryControl(reporter: PluginReporter): Unit =
    throw new NotSupported("local state for its outputs")

  override def setIndividualRemoteSupervisoryControl(reporter: PluginReporter, index: Int): Unit =
    throw new NotSupported("local state for its outputs")

  // ------------------------------------------------- unsolicited responses

  override def enableUnsolicitedResponse(reporter: PluginReporter, enabled: Boolean): Unit =
    powerCycle(reporter, s"Set unsolicited responses to $enabled", "unsolicited" -> enabled)

  override def setUnsolicitedResponseTimeout(reporter: PluginReporter, timeoutMs: Int): Unit =
    powerCycle(
      reporter,
      s"Set the unsolicited confirmation timeout to $timeoutMs ms",
      "unsolicited_confirm_timeout" -> timeoutMs / 1000.0)

  override def setMaxUnsolicitedRetries(reporter: PluginReporter, numRetries: Option[Int]): Unit =
    powerCycle(
      reporter,
      s"Set the unsolicited retries to ${numRetries.fold("no limit")(_.toString)}",
      "unsolicited_retries" -> numRetries.fold[ujson.Value](ujson.Null)(ujson.Num(_)))

  override def setMasterAddress(reporter: PluginReporter, address: Int): Unit =
    powerCycle(reporter, s"Set the master address to $address", "master_address" -> address)

  // One change of one input, in a class the master has enabled for unsolicited reporting if it has enabled any.
  override def generateUnsolicitedEvents(reporter: PluginReporter, timing: ActionTiming): ActionResult = {
    val s = state()
    val enabled = s("unsolicited_classes").arr.map(_.num.toInt).toList
    val eventClass = (if (enabled.isEmpty) List(1, 2, 3) else enabled)
      .find(c => inClass(s, "BI", c).nonEmpty || inClass(s, "AI", c).nonEmpty)
      .getOrElse(throw new Exception("The device has no input that reports events"))
    generate(reporter, exactClassChanges(s, eventClass, 1))
    ActionResult.Performed
  }

  override def generateNotEnoughUnsolicitedEvents(reporter: PluginReporter): Unit =
    throw new NotSupported("minimum number of events before it sends an unsolicited response")

  // ------------------------------------------------------------------ misc

  override def recordCurrentCounterValues(reporter: PluginReporter): Unit = {
    val s = state()
    val values = indices(s, "counters").map(index => index -> s("counters")(index.toString).num.toLong).toMap
    recordedCounters = Some(values)
    reporter.log(s"The device's counters stand at ${byIndex(values)}")
  }

  override def generateTimeEvent(reporter: PluginReporter): Unit = {
    val s = state()
    val before = System.currentTimeMillis()
    // a binary input event, since those carry their time
    val eventClass = List(1, 2, 3).find(inClass(s, "BI", _).nonEmpty)
      .getOrElse(throw new Exception("The device has no binary input that reports events"))
    val event = generate(reporter, exactClassChanges(s, eventClass, 1))
    val after = System.currentTimeMillis()
    timeEvent = Some(TimeEvent(event.head, before, after))
    reporter.log(s"Generated ${event.head} between $before and $after by this machine's clock")
  }

  override def setMaxFragmentSize(reporter: PluginReporter, maxFragmentSize: Int): Unit =
    powerCycle(reporter, s"Set the largest fragment sent to $maxFragmentSize octets", "max_response" -> maxFragmentSize)

  // Enough binary input events that reading them takes more than one fragment of the size the device is set to.
  override def generateMultiFragmentResponse(reporter: PluginReporter): Unit = {
    val s = state()
    val index = List(1, 2, 3).flatMap(inClass(s, "BI", _)).headOption
      .getOrElse(throw new Exception("The device has no binary input that reports events"))
    // an event without time is at least two octets, so this many cannot fit one fragment in any variation
    val count = s("settings")("max_response").num.toInt / 2 + 1
    generate(reporter, toggles(s, List.fill(count)(index)))
  }

  // ===================
  // Message validations
  // ===================

  // ---------------------------------------------------------- static values

  override def verifyAllStaticCurrentValues(
      reporter: CheckReporter,
      isClass0: Boolean,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] = {
    val s = state()
    points.foreach(p => checkStatic(s, p))
    if (isClass0) {
      // a class 0 response carries every installed input
      List(("BI", "binary input"), ("AI", "analog input"), ("CTR", "counter")).foreach { case (kind, name) =>
        val reported = points.collect { case p if staticKind(p.point).contains(kind) => p.idx }.toSet
        val missing = s("installed")(kind).arr.map(_.num.toInt).filterNot(reported.contains)
        if (missing.nonEmpty) throw new Exception(s"The response leaves out $name ${missing.mkString(", ")}")
      }
    }
    reporter.log(s"Each of the ${points.size} values reported is the value the device holds")
    None
  }

  override def verifyInputCurrentValues[P <: MeasurementPoint](
      reporter: CheckReporter,
      kind: InputKind[P],
      points: Seq[GenIndexedPoint[P]]): Option[DeferredCheck] = {
    val wanted = kind match {
      case InputKind.BinaryInput => "BI"
      case InputKind.AnalogInput => "AI"
      case InputKind.Counter => "CTR"
      case InputKind.DoubleBitInput => throw new NotSupported("double-bit binary inputs")
    }
    val s = state()
    points.foreach { p =>
      p.point match {
        // A counter frozen with nothing counted since holds what the counter holds now. The procedures ask for
        // this check of frozen counters only straight after a freeze.
        case frozen: CounterPoint if frozen.isFrozen && wanted == "CTR" =>
          expectValue(s"frozen counter ${p.idx}", s("counters")(p.idx.toString).num, frozen.value.toDouble)
        case other =>
          if (!staticKind(other).contains(wanted)) throw new Exception(s"Index ${p.idx} is not a ${kind.name}: $other")
          checkStatic(s, GenIndexedPoint[MeasurementPoint](p.idx, other))
      }
    }
    val reported = points.map(_.idx).toSet
    val missing = s("installed")(wanted).arr.map(_.num.toInt).filterNot(reported.contains)
    if (missing.nonEmpty) throw new Exception(s"The response leaves out ${kind.name} ${missing.mkString(", ")}")
    reporter.log(s"Each of the ${points.size} ${kind.name} values reported is the value the device holds")
    None
  }

  override def verifyRecordedCounterValues(
      reporter: CheckReporter,
      points: Seq[GenIndexedPoint[CounterPoint]]): Option[DeferredCheck] = {
    val recorded = recordedCounters.getOrElse(throw new Exception("No counter values were recorded"))
    if (points.isEmpty) throw new Exception("The response holds no counter")
    points.foreach { p =>
      val expected = recorded.getOrElse(p.idx, throw new Exception(s"No value was recorded for counter ${p.idx}"))
      expectValue(s"counter ${p.idx}", expected.toDouble, p.point.value.toDouble)
    }
    reporter.log(s"Each counter reported equals the value recorded: ${byIndex(recorded)}")
    None
  }

  // which of the device's kinds a static object reports, if it is one the device has
  private def staticKind(point: MeasurementPoint): Option[String] = point match {
    case p if p.pointType != PointType.Static => None
    case _: BinaryPoint => Some("BI")
    case p: AnalogPoint if !p.isFrozen => Some("AI")
    case p: CounterPoint if !p.isFrozen => Some("CTR")
    case _: BinaryOutputStatusPoint => Some("BO")
    case _: AnalogOutputStatusPoint => Some("AO")
    case _ => None
  }

  // one static object against what the device holds for that point
  private def checkStatic(state: ujson.Obj, p: GenIndexedPoint[MeasurementPoint]): Unit = {
    val index = p.idx.toString
    def held(name: String, what: String): ujson.Value =
      state(name).obj.getOrElse(index, throw new Exception(s"The device has no $what ${p.idx}"))
    p.point match {
      case point if point.pointType != PointType.Static =>
        throw new Exception(s"Index ${p.idx} is an event where a static value was expected: $point")
      case point: BinaryPoint =>
        expectValue(s"binary input ${p.idx}", bit(held("binary", "binary input").bool), bit(point.value))
      case point: AnalogPoint if !point.isFrozen =>
        expectValue(s"analog input ${p.idx}", held("analog", "analog input").num, point.value)
      case point: CounterPoint if !point.isFrozen =>
        expectValue(s"counter ${p.idx}", held("counters", "counter").num, point.value.toDouble)
      case point: BinaryOutputStatusPoint =>
        expectValue(s"binary output ${p.idx}", bit(held("binary_outputs", "binary output").bool), bit(point.value))
      case point: AnalogOutputStatusPoint =>
        expectValue(s"analog output ${p.idx}", held("analog_outputs", "analog output").num, point.value)
      case other =>
        // the device's record of a frozen value is not on the control channel, so one here cannot be checked
        throw new Exception(s"The plugin has no record to check index ${p.idx} against: $other")
    }
  }

  private def bit(value: Boolean): Double = if (value) 1.0 else 0.0

  private def expectValue(what: String, held: Double, reported: Double): Unit =
    if (held != reported) throw new Exception(s"The device holds $held for $what, and the response reports $reported")

  private def byIndex(values: Map[Int, Long]): String =
    values.toList.sorted.map { case (index, value) => s"$index: $value" }.mkString(", ")

  // ----------------------------------------------------------------- events

  private def show(kind: String, value: Double): String =
    if (kind == "BI") (value != 0).toString else value.toString

  private def describe(p: GenIndexedPoint[MeasurementPoint]): String = {
    val time = p.point.timestamp.fold("no time")(t => s"time ${t.value}")
    p.point match {
      case b: BinaryPoint => s"BI${p.idx} = ${b.value}, $time"
      case a: AnalogPoint => s"AI${p.idx} = ${a.value}, $time"
      case other => s"index ${p.idx}: $other"
    }
  }

  // Why a reported event is not the generated one, or None if it is. An event that carries a time must carry the
  // time the device recorded for the change.
  private def difference(expected: Generated, p: GenIndexedPoint[MeasurementPoint]): Option[String] = {
    val same = p.point match {
      case point if point.pointType != PointType.Event => false
      case b: BinaryPoint => expected.kind == "BI" && expected.index == p.idx && bit(b.value) == expected.value
      case a: AnalogPoint =>
        !a.isFrozen && expected.kind == "AI" && expected.index == p.idx && a.value == expected.value
      case _ => false
    }
    if (!same) Some(s"expected $expected, and the response has ${describe(p)}")
    else
      p.point.timestamp match {
        case Some(t) if t.value != expected.timeMs =>
          Some(
            s"${describe(p)} carries a time ${t.value - expected.timeMs} ms from the ${expected.timeMs} the device " +
              "recorded")
        case _ => None
      }
  }

  private def isBinary(p: GenIndexedPoint[MeasurementPoint]): Boolean = p.point.isInstanceOf[BinaryPoint]

  // The response holds exactly the expected events: the binary input events in the order they occurred, and each
  // analog input's events in the order they occurred.
  private def expectEvents(expected: List[Generated], points: Seq[GenIndexedPoint[MeasurementPoint]]): Unit = {
    def inOrder(what: String, want: List[Generated], got: List[GenIndexedPoint[MeasurementPoint]]): Unit = {
      if (want.size != got.size) {
        throw new Exception(
          s"The device generated ${want.size} $what event(s) and the response holds ${got.size}. Generated: " +
            s"${want.mkString("; ")}. Reported: ${got.map(describe).mkString("; ")}")
      }
      want.zip(got).foreach { case (w, g) => difference(w, g).foreach(reason => throw new Exception(reason)) }
    }
    val stray = points.filterNot(p => p.point.isInstanceOf[BinaryPoint] || p.point.isInstanceOf[AnalogPoint])
    if (stray.nonEmpty) {
      throw new Exception(
        s"The response holds events of a kind that was not generated: ${stray.map(describe).mkString("; ")}")
    }
    inOrder("binary input", expected.filter(_.kind == "BI"), points.filter(isBinary).toList)
    val analog = points.filterNot(isBinary).toList
    (expected.filter(_.kind == "AI").map(_.index) ++ analog.map(_.idx)).distinct.foreach { index =>
      val generated = expected.filter(e => e.kind == "AI" && e.index == index)
      inOrder(s"analog input $index", generated, analog.filter(_.idx == index))
    }
  }

  private def latest: List[Generated] =
    batches.lastOption.getOrElse(throw new Exception("No events were generated before this check"))

  // The generated events the device still holds, of those given. Where the device says it keeps one event for
  // each analog input, an analog event is gone once the same input has changed again.
  private def kept(events: List[Generated]): List[Generated] = {
    if (!state()("analog_events_latest_only").bool) events
    else {
      val all = batches.toList.flatten
      events.filter { e =>
        e.kind != "AI" || !all.drop(all.indexWhere(_ eq e) + 1).exists(l => l.kind == "AI" && l.index == e.index)
      }
    }
  }

  private def expected(expectation: EventExpectation, wanted: Generated => Boolean): List[Generated] =
    expectation match {
      case EventExpectation.LatestBatch => kept(latest.filter(wanted))
      case EventExpectation.RemainingLatestBatch => kept(latest.filter(wanted).filterNot(_.checked))
      case EventExpectation.AllGeneratedBatches => kept(batches.toList.flatten.filter(wanted))
      case other => throw new Exception(s"The plugin does not check $other here")
    }

  // each returned event is one the device generated; there may be none
  private def expectOnlyGenerated(points: Seq[GenIndexedPoint[MeasurementPoint]]): Unit = {
    val all = batches.toList.flatten
    points.foreach { p =>
      if (!all.exists(difference(_, p).isEmpty)) {
        throw new Exception(s"The response holds an event the device did not generate: ${describe(p)}")
      }
    }
  }

  private def verifyEvents(
      reporter: CheckReporter,
      what: String,
      expectation: EventExpectation,
      wanted: Generated => Boolean,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] = {
    expectation match {
      case EventExpectation.ReturnedEventsOnly =>
        expectOnlyGenerated(points)
        reporter.log(s"Each of the ${points.size} $what event(s) returned is one the device generated")
      case EventExpectation.CurrentValuesWithOptionalEarlier =>
        // each input changed in the latest batch ends on the value the device holds now; anything before that is
        // an earlier event of the same kind
        expectOnlyGenerated(points)
        val changed = latest.filter(wanted)
        if (changed.isEmpty) throw new Exception(s"The latest batch generated no $what event")
        changed.map(e => (e.kind, e.index)).distinct.foreach { case (kind, index) =>
          val last = changed.filter(e => e.kind == kind && e.index == index).last
          val reported = points.filter(samePoint(last, _))
          if (reported.isEmpty) throw new Exception(s"The response holds no event for $kind$index, which is now $last")
          difference(last, reported.last).foreach(reason => throw new Exception(reason))
        }
        reporter.log(s"The $what events end on the values the device holds: ${changed.mkString("; ")}")
      case _ =>
        val events = expected(expectation, wanted)
        expectEvents(events, points)
        reporter.log(s"The response holds the ${events.size} $what event(s) expected ($expectation), in order")
    }
    None
  }

  private def samePoint(event: Generated, p: GenIndexedPoint[MeasurementPoint]): Boolean = p.point match {
    case _: BinaryPoint => event.kind == "BI" && event.index == p.idx
    case a: AnalogPoint => !a.isFrozen && event.kind == "AI" && event.index == p.idx
    case _ => false
  }

  private def verifyFirst(
      reporter: CheckReporter,
      what: String,
      wanted: Generated => Boolean,
      point: GenIndexedPoint[MeasurementPoint]): Option[DeferredCheck] = {
    val first = latest.filter(wanted).headOption
      .getOrElse(throw new Exception(s"The latest batch generated no $what event"))
    difference(first, point).foreach(reason => throw new Exception(reason))
    first.checked = true
    reporter.log(s"The response holds the first $what event generated: $first")
    None
  }

  private def kindName(kind: InputKind[?]): String = kind match {
    case InputKind.BinaryInput => "BI"
    case InputKind.AnalogInput => "AI"
    case InputKind.Counter => throw new NotSupported("counter change events")
    case InputKind.DoubleBitInput => throw new NotSupported("double-bit binary inputs")
  }

  private def inClasses(eventClass: EventClass): Generated => Boolean = eventClass match {
    case EventClass.All => _ => true
    case one =>
      val number = classOf(one)
      _.eventClass == number
  }

  private def widen[P <: MeasurementPoint](p: GenIndexedPoint[P]): GenIndexedPoint[MeasurementPoint] =
    GenIndexedPoint[MeasurementPoint](p.idx, p.point)

  override def verifyInputEvents[P <: MeasurementPoint](
      reporter: CheckReporter,
      kind: InputKind[P],
      expectation: EventExpectation,
      points: Seq[GenIndexedPoint[P]]): Option[DeferredCheck] = {
    val name = kindName(kind)
    verifyEvents(reporter, kind.name, expectation, _.kind == name, points.map(widen))
  }

  override def verifyFirstInputEvent[P <: MeasurementPoint](
      reporter: CheckReporter,
      kind: InputKind[P],
      point: GenIndexedPoint[P]): Option[DeferredCheck] = {
    val name = kindName(kind)
    verifyFirst(reporter, kind.name, _.kind == name, widen(point))
  }

  override def verifyClassEvents(
      reporter: CheckReporter,
      eventClass: EventClass,
      expectation: EventExpectation,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] =
    verifyEvents(reporter, eventClass.toString, expectation, inClasses(eventClass), points)

  override def verifyFirstClassEvent(
      reporter: CheckReporter,
      eventClass: EventClass,
      point: GenIndexedPoint[MeasurementPoint]): Option[DeferredCheck] =
    verifyFirst(reporter, eventClass.toString, inClasses(eventClass), point)

  // ---------------------------------------------------------- analog outputs

  // An analog output holds a whole number, so the value reported is the value sent, and the device holds it too.
  override def checkAnalogOutputTolerance(
      reporter: CheckReporter,
      expectedValue: Double,
      actualValue: Double): Option[DeferredCheck] = {
    if (expectedValue != actualValue) {
      throw new Exception(s"The value sent was $expectedValue and the device reports $actualValue")
    }
    val held = state()("analog_outputs").obj.collect { case (index, value) if !value.isNull => index -> value.num }
    if (!held.values.exists(_ == expectedValue)) {
      throw new Exception(s"No analog output of the device holds $expectedValue; they hold ${ujson.write(held)}")
    }
    reporter.log(s"The device holds $expectedValue, the value sent and the value reported")
    None
  }

  // -------------------------------------------------- unsolicited responses

  private def sameEvent(a: GenIndexedPoint[MeasurementPoint], b: GenIndexedPoint[MeasurementPoint]): Boolean =
    a.idx == b.idx && a.point == b.point

  override def verifyPolledDataDoNotRepeatUnsolicitedData(
      reporter: CheckReporter,
      unsolicitedResponsePoints: Seq[GenIndexedPoint[MeasurementPoint]],
      polledResponsePoints: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] = {
    // every event here was generated by the device, so one reported both ways would be the same object twice
    expectOnlyGenerated(unsolicitedResponsePoints)
    expectOnlyGenerated(polledResponsePoints)
    val repeated = polledResponsePoints.filter(p => unsolicitedResponsePoints.exists(sameEvent(_, p)))
    if (repeated.nonEmpty) {
      throw new Exception(s"The polled response repeats events of the unsolicited one: ${repeated.map(describe)}")
    }
    reporter.log(
      s"None of the ${polledResponsePoints.size} polled event(s) repeats one of the " +
        s"${unsolicitedResponsePoints.size} unsolicited event(s)")
    None
  }

  override def verifyResponseRetainsEvents(
      reporter: CheckReporter,
      previous: Seq[GenIndexedPoint[MeasurementPoint]],
      current: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] = {
    expectOnlyGenerated(previous)
    expectOnlyGenerated(current)
    val lost = previous.filterNot(p => current.exists(sameEvent(_, p)))
    if (lost.nonEmpty) {
      throw new Exception(s"The response no longer holds events the earlier one reported: ${lost.map(describe)}")
    }
    reporter.log(s"The response holds each of the ${previous.size} event(s) the earlier one reported")
    None
  }

  // ------------------------------------------------------------------- time

  // The outstation reports how long it held the request. Nothing else measures that, so the check is that the
  // figure is one a request answered at once could have.
  override def verifyDelayMeasurementAccuracy(reporter: CheckReporter, delayMs: Long): Option[DeferredCheck] = {
    if (delayMs < 0 || delayMs > settings.timeToleranceMs) {
      throw new Exception(
        s"The device reports a delay of $delayMs ms; up to ${settings.timeToleranceMs} ms is accepted")
    }
    reporter.log(s"The device reports a delay of $delayMs ms, within ${settings.timeToleranceMs} ms")
    None
  }

  override def verifyTimestamp(
      reporter: CheckReporter,
      points: Seq[GenIndexedPoint[MeasurementPoint]]): Option[DeferredCheck] = {
    val made = timeEvent.getOrElse(throw new Exception("No event was generated for the time check"))
    val reported = points.filter(p => samePoint(made.event, p) && p.point.timestamp.isDefined)
      .find(p => difference(made.event, p).isEmpty)
      .getOrElse(throw new Exception(
        s"The response does not hold ${made.event} with its time. It holds: ${points.map(describe).mkString("; ")}"))
    val time = reported.point.timestamp.get.value
    val tolerance = settings.timeToleranceMs
    if (time < made.before - tolerance || time > made.after + tolerance) {
      throw new Exception(
        s"The event's time is $time. It was generated between ${made.before} and ${made.after} by this machine's " +
          s"clock, and $tolerance ms either side is accepted")
    }
    reporter.log(
      s"The event's time, $time, is the time the device recorded, and within $tolerance ms of when it was generated " +
        s"(${made.before} to ${made.after})")
    None
  }

  // ------------------------------------------------------ device attributes

  override def verifyDeviceAttributes(
      reporter: CheckReporter,
      attributes: Seq[(Int, AttributeValue)]): Option[DeferredCheck] =
    throw new NotSupported("device attributes")
}
