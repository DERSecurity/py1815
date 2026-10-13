// Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.

package py1815conformance

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{ Files, Path, Paths }

import io.stepfunc.dnp3c.conformance.Harness
import io.stepfunc.dnp3c.conformance.api.options.{ ChannelOptions, LinkOptions, TestOptions }
import io.stepfunc.dnp3c.conformance.api.{
  ConfigurationException, HarnessExecutionException, Options, ProcedureOutcome, ProcedureResult
}

import scala.collection.mutable
import scala.util.control.NonFatal

/**
 * Runs the conformance procedures against the py1815 outstation with nobody present.
 *
 *   -config <file>   the dnp3c configuration; device.ini when not given
 *   -run <id>        a procedure, a section, or all; all when not given
 *
 * The harness stops a run at the first procedure that fails. This program then runs each procedure the harness did
 * not reach, one at a time, so one failure does not hide the outcome of the rest. It writes the harness's report,
 * and outcomes.json beside it with every procedure's outcome and the harness's own words for it. It exits with 0
 * only if no procedure failed.
 *
 * Two settings come from the environment, because they differ from one machine to the next:
 *
 *   PY1815_CONFORMANCE_PYTHON    the Python interpreter that has py1815 installed (required)
 *   PY1815_CONFORMANCE_FIXTURE   the device script; ../conformance_outstation.py when not set
 */
object Main {

  private val pythonVariable = "PY1815_CONFORMANCE_PYTHON"
  private val fixtureVariable = "PY1815_CONFORMANCE_FIXTURE"

  // a run that cannot start: the command line, the environment or the configuration is wrong
  private final class CannotStart(message: String) extends Exception(message)

  def main(args: Array[String]): Unit = {
    val code =
      try run(args.toList)
      catch {
        case ex: CannotStart =>
          System.err.println(ex.getMessage)
          2
      }
    sys.exit(code)
  }

  private def setting(name: String): Option[String] = sys.env.get(name).map(_.trim).filter(_.nonEmpty)

  private def run(args: List[String]): Int = {
    val (config, id) = arguments(args, Paths.get("device.ini"), "all")
    val python = setting(pythonVariable).getOrElse(
      throw new CannotStart(s"Set $pythonVariable to the Python interpreter that has py1815 installed."))
    val script = Paths.get(setting(fixtureVariable).getOrElse("../conformance_outstation.py"))

    val options =
      try Options.load(config)
      catch {
        case ex: ConfigurationException => throw new CannotStart(ex.getMessage)
        case ex: java.io.IOException => throw new CannotStart(s"Could not read $config: $ex")
      }
    val channel = ChannelOptions(options)
    if (channel.host != "127.0.0.1") {
      throw new CannotStart(
        s"tcp.device.address is ${channel.host}; the device this program starts listens on 127.0.0.1")
    }
    val output = Paths.get(options.get(TestOptions.outputDirectory))
    val command = FixtureCommand(
      python = python,
      script = script,
      port = channel.port,
      outstation = options.get(LinkOptions.destination),
      master = options.get(LinkOptions.source),
      log = output.resolve("outstation.log")
    )
    val harness = new Harness(options, new Py1815Plugin(PluginSettings(command)))

    // each procedure's outcome and the harness's words for it, in the order the procedures ran
    val outcomes = mutable.LinkedHashMap[String, (String, String)]()
    var broken = false

    def record(results: List[ProcedureResult]): Unit = results.foreach { r =>
      outcomes(r.id) = r.outcome match {
        case ProcedureOutcome.Passed => ("passed", "")
        case ProcedureOutcome.Skipped(reason) => ("skipped", reason)
        case ProcedureOutcome.Failed(message) => ("failed", message)
      }
    }

    // Run one procedure or section, and return the procedures the run stopped short of.
    def attempt(what: String): List[String] =
      try {
        val summary = harness.run(what)
        record(summary.results)
        summary.unreached
      } catch {
        case ex: IllegalArgumentException => throw new CannotStart(ex.getMessage)
        case ex: HarnessExecutionException =>
          // the harness or the plugin failed around the procedure, which then has no result of its own
          broken = true
          record(ex.partial.results)
          outcomes.getOrElseUpdate(ex.procedureId, ("error", ex.getMessage))
          ex.partial.unreached
      }

    try {
      // each procedure the first run did not reach is a run of its own, which reaches it whatever came before
      attempt(id).foreach(attempt)
    } finally {
      try harness.writeReport()
      catch {
        case NonFatal(ex) =>
          System.err.println(s"Failed to write the report: ${ex.getMessage}")
          broken = true
      }
    }

    try write(output.resolve("outcomes.json"), outcomes)
    catch {
      case ex: java.io.IOException =>
        System.err.println(s"Failed to write outcomes.json: $ex")
        broken = true
    }

    println()
    outcomes.foreach { case (procedure, (outcome, detail)) =>
      if (outcome != "passed") println(s"$procedure: $outcome${if (detail.isEmpty) "" else s" ($detail)"}")
    }
    val counts = outcomes.values.groupBy(_._1).view.mapValues(_.size).toList.sorted
    println(counts.map { case (outcome, count) => s"$count $outcome" }.mkString(", "))

    val failed = outcomes.values.exists { case (outcome, _) => outcome == "failed" || outcome == "error" }
    if (broken || failed) 1 else 0
  }

  private def arguments(args: List[String], config: Path, id: String): (Path, String) = args match {
    case Nil => (config, id)
    case "-config" :: file :: rest =>
      val path =
        try Paths.get(file)
        catch {
          case ex: java.nio.file.InvalidPathException => throw new CannotStart(s"-config is not a path: ${ex.getMessage}")
        }
      arguments(rest, path, id)
    case "-run" :: what :: rest => arguments(rest, config, what)
    case other :: _ =>
      throw new CannotStart(
        s"Unexpected argument: $other\nusage: [-config <file>] [-run <procedure, section or all>]")
  }

  private def write(file: Path, outcomes: mutable.LinkedHashMap[String, (String, String)]): Unit = {
    val procedures = ujson.Obj()
    outcomes.foreach { case (id, (outcome, detail)) =>
      procedures(id) = ujson.Obj("outcome" -> outcome, "detail" -> detail)
    }
    Files.createDirectories(file.toAbsolutePath.getParent)
    Files.write(file, (ujson.write(ujson.Obj("procedures" -> procedures), indent = 2) + "\n").getBytes(UTF_8))
  }
}
