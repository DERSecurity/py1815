// Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.

package py1815conformance

import java.io.{ BufferedReader, BufferedWriter, InputStreamReader, OutputStreamWriter }
import java.net.{ InetAddress, Socket }
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{ Files, Path }
import java.util.concurrent.{ CompletableFuture, TimeUnit, TimeoutException }

/**
 * Where the device under test comes from, and the addresses it is started with.
 *
 * @param python the Python interpreter that has py1815 installed
 * @param script interop/conformance_outstation.py
 * @param port the port the outstation listens on
 * @param outstation the outstation's link address
 * @param master the link address of the master the outstation serves
 * @param log the file the device's own log is appended to
 */
final case class FixtureCommand(python: String, script: Path, port: Int, outstation: Int, master: Int, log: Path)

/** A request the control channel refused, or a device that could not be started or reached. */
final class FixtureException(message: String, cause: Throwable = null) extends Exception(message, cause)

/**
 * The device under test: the Python process that serves the outstation, and the control channel to it.
 *
 * Starting it returns once the outstation accepts connections. Everything here stays on the loopback interface.
 */
final class Fixture(command: FixtureCommand) extends AutoCloseable {

  private val startTimeoutSeconds = 60L
  private val answerTimeoutMs = 120000
  private val exitTimeoutSeconds = 10L

  private val process: Process = {
    if (!Files.isRegularFile(command.script)) {
      throw new FixtureException(s"The device script is not at ${command.script.toAbsolutePath.normalize}")
    }
    Files.createDirectories(command.log.toAbsolutePath.getParent)
    val builder = new ProcessBuilder(
      command.python,
      "-u",
      command.script.toString,
      "--port",
      command.port.toString,
      "--outstation-address",
      command.outstation.toString,
      "--master-address",
      command.master.toString
    )
    builder.redirectError(ProcessBuilder.Redirect.appendTo(command.log.toFile))
    try builder.start()
    catch {
      case ex: java.io.IOException =>
        throw new FixtureException(s"Could not start the device with ${command.python}: ${ex.getMessage}", ex)
    }
  }

  private val socket: Socket =
    try {
      process.getOutputStream.close()
      new Socket(InetAddress.getLoopbackAddress, controlPort())
    } catch {
      case ex: Throwable =>
        process.destroyForcibly()
        throw ex
    }
  socket.setSoTimeout(answerTimeoutMs)
  private val reader = new BufferedReader(new InputStreamReader(socket.getInputStream, UTF_8))
  private val writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream, UTF_8))

  // The device prints one line once both of its listeners are bound: the address of its control channel.
  private def controlPort(): Int = {
    val announced = new CompletableFuture[String]()
    val drain: Runnable = () => {
      val lines = new BufferedReader(new InputStreamReader(process.getInputStream, UTF_8))
      try {
        announced.complete(lines.readLine())
        // nothing else is expected, and anything that does come must not fill the pipe
        while (lines.readLine() != null) {}
      } catch {
        case ex: java.io.IOException =>
          announced.completeExceptionally(ex)
          ()
      }
    }
    val stdout = new Thread(drain)
    stdout.setDaemon(true)
    stdout.start()

    val line =
      try announced.get(startTimeoutSeconds, TimeUnit.SECONDS)
      catch {
        case _: TimeoutException =>
          throw new FixtureException(
            s"The device did not start within $startTimeoutSeconds s; its log is ${command.log}")
      }
    val prefix = "control channel listening on 127.0.0.1:"
    if (line == null || !line.startsWith(prefix)) {
      throw new FixtureException(
        s"The device did not start (it printed ${if (line == null) "nothing" else s"'$line'"}); " +
          s"its log is ${command.log}")
    }
    line.substring(prefix.length).trim.toInt
  }

  /** Send one request to the control channel and return its answer, throwing if the device refused it. */
  def ask(op: String, fields: (String, ujson.Value)*): ujson.Obj = synchronized {
    val request = ujson.Obj("op" -> ujson.Str(op))
    fields.foreach { case (name, value) => request(name) = value }
    val line =
      try {
        writer.write(ujson.write(request))
        writer.write("\n")
        writer.flush()
        reader.readLine()
      } catch {
        case ex: java.io.IOException =>
          throw new FixtureException(s"The control channel failed during '$op': ${ex.getMessage}", ex)
      }
    if (line == null) throw new FixtureException(s"The device closed the control channel during '$op'")
    val answer = ujson.read(line).obj
    if (!answer("ok").bool) throw new FixtureException(s"The device refused '$op': ${answer("error").str}")
    ujson.Obj.from(answer)
  }

  /** Stop the device and wait for it to exit, so its port is free for the next one. */
  override def close(): Unit = {
    try if (process.isAlive) ask("stop")
    catch { case _: FixtureException => }
    try socket.close()
    catch { case _: java.io.IOException => }
    if (!process.waitFor(exitTimeoutSeconds, TimeUnit.SECONDS)) {
      process.destroyForcibly()
      process.waitFor(exitTimeoutSeconds, TimeUnit.SECONDS)
    }
  }

  /** End the process at once, for a JVM that is exiting. */
  def kill(): Unit = process.destroyForcibly()
}
