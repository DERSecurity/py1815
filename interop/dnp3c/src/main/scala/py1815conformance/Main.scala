// Copyright 2026 DER Security Corp. Licensed under the GNU General Public License,
// version 3 only: see LICENSE in this directory.

package py1815conformance

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{ Files, Path, Paths }

import io.stepfunc.dnp3c.conformance.{ Harness, Revisions }
import io.stepfunc.dnp3c.conformance.api.options.{ ChannelOptions, LinkOptions, TestOptions }
import io.stepfunc.dnp3c.conformance.api.{
  ConfigurationException, HarnessExecutionException, Options, ProcedureOutcome, ProcedureResult
}

import scala.collection.mutable
import scala.util.control.NonFatal

/**
 * Runs the conformance procedures against the py1815 outstation with nobody present.
 *
 *   -rev <id>        the revision of the certification procedure to run, e.g. 3.1r1 or 2.7 (required)
 *   -config <file>   the dnp3c configuration; device.ini when not given
 *   -run <id>        a procedure, a section, or all; all when not given
 *
 * The harness stops a run at the first procedure that fails. This program then runs each procedure the harness did
 * not reach, one at a time, so one failure does not hide the outcome of the rest. It writes the harness's report,
 * in the revision's folder for the subset level, and outcomes.json beside it with every procedure's outcome and the harness's own words for it. It exits with 0
 * only if no procedure failed.
 *
 * Two settings come from the environment, because they differ from one machine to the next:
 *
 *   PY1815_CONFORMANCE_PYTHON    the Python interpreter that has py1815 installed (required)
 *   PY1815_CONFORMANCE_FIXTURE   the device script; ../conformance_outstation.py when not set
 */
// One procedure's outcome, the harness's words for it, and what it noted or warned about a pass.
private final case class Outcome(
    outcome: String,
    detail: String,
    notes: List[String] = Nil,
    warnings: List[String] = Nil)

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
    val (rev, config, id) = arguments(args, None, Paths.get("device.ini"), "all")
    val revision = Revisions.find(rev.getOrElse(throw new CannotStart(s"Name the revision with -rev: $revisionIds")))
      .getOrElse(throw new CannotStart(s"Unknown revision ${rev.get}: $revisionIds"))
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
    val loopback =
      try java.net.InetAddress.getByName(channel.host).isLoopbackAddress
      catch { case _: java.net.UnknownHostException => false }
    if (!loopback) {
      throw new CannotStart(
        s"tcp.device.address is ${channel.host}; the device this program starts listens on a loopback address")
    }
    val output =
      try revision.runDirectory(options)
      catch { case ex: ConfigurationException => throw new CannotStart(ex.getMessage) }
    val command = FixtureCommand(
      python = python,
      script = script,
      host = channel.host,
      port = channel.port,
      outstation = options.get(LinkOptions.destination),
      master = options.get(LinkOptions.source),
      log = output.resolve("outstation.log")
    )
    val harness = new Harness(options, new Py1815Plugin(PluginSettings(command)), revision)

    // each procedure's outcome and the harness's words for it, in the order the procedures ran
    val outcomes = mutable.LinkedHashMap[String, Outcome]()
    var broken = false

    def record(results: List[ProcedureResult]): Unit = results.foreach { r =>
      val (outcome, detail) = r.outcome match {
        case ProcedureOutcome.Passed => ("passed", "")
        case ProcedureOutcome.Skipped(reason) => ("skipped", reason)
        case ProcedureOutcome.Excluded(reason) => ("excluded", reason)
        case ProcedureOutcome.Failed(message) => ("failed", message)
      }
      outcomes(r.id) = Outcome(outcome, detail, r.notes, r.warnings)
    }

    // Run one procedure or section, and return the procedures the run stopped short of.
    def attempt(what: String): List[String] =
      try {
        val summary = harness.run(what)
        record(summary.results)
        summary.unreached
      } catch {
        case ex: IllegalArgumentException => throw new CannotStart(ex.getMessage)
        case ex: ConfigurationException => throw new CannotStart(ex.getMessage)
        case ex: HarnessExecutionException =>
          // the harness or the plugin failed around the procedure, which then has no result of its own
          broken = true
          record(ex.partial.results)
          outcomes.getOrElseUpdate(ex.procedureId, Outcome("error", ex.getMessage))
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
    outcomes.foreach { case (procedure, Outcome(outcome, detail, _, warnings)) =>
      if (outcome != "passed") println(s"$procedure: $outcome${if (detail.isEmpty) "" else s" ($detail)"}")
      warnings.foreach(warning => println(s"$procedure: warning: $warning"))
    }
    val counts = outcomes.values.groupBy(_.outcome).view.mapValues(_.size).toList.sorted
    println(counts.map { case (outcome, count) => s"$count $outcome" }.mkString(", "))

    val failed = outcomes.values.exists(o => o.outcome == "failed" || o.outcome == "error")
    if (broken || failed) 1 else 0
  }

  private def revisionIds: String = Revisions.list.map(_.id).mkString("one of ", ", ", "")

  private def arguments(
      args: List[String],
      rev: Option[String],
      config: Path,
      id: String): (Option[String], Path, String) = args match {
    case Nil => (rev, config, id)
    case "-rev" :: which :: rest => arguments(rest, Some(which), config, id)
    case "-config" :: file :: rest =>
      val path =
        try Paths.get(file)
        catch {
          case ex: java.nio.file.InvalidPathException =>
            throw new CannotStart(s"-config is not a path: ${ex.getMessage}")
        }
      arguments(rest, rev, path, id)
    case "-run" :: what :: rest => arguments(rest, rev, config, what)
    case other :: _ =>
      throw new CannotStart(
        s"Unexpected argument: $other\nusage: -rev <revision> [-config <file>] [-run <procedure, section or all>]")
  }

  private def write(file: Path, outcomes: mutable.LinkedHashMap[String, Outcome]): Unit = {
    val procedures = ujson.Obj()
    outcomes.foreach { case (id, Outcome(outcome, detail, notes, warnings)) =>
      procedures(id) = ujson.Obj(
        "outcome" -> outcome,
        "detail" -> detail,
        "notes" -> ujson.Arr.from(notes.map(ujson.Str(_))),
        "warnings" -> ujson.Arr.from(warnings.map(ujson.Str(_))))
    }
    Files.createDirectories(file.toAbsolutePath.getParent)
    Files.write(file, (ujson.write(ujson.Obj("procedures" -> procedures), indent = 2) + "\n").getBytes(UTF_8))
  }
}
