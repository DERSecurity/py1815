"""A headless browser, driven over the DevTools protocol, for testing the console.

The console is a web page, and the only honest test of a web page is to load
it in a browser. This starts Chrome, Chromium or Edge with no window, speaks
the DevTools protocol to it over a WebSocket, and exposes the little a test
needs: go to a page, run an expression in it, wait for something to be true.

It needs no package the suite does not already have. The WebSocket client
below is the part of RFC 6455 this conversation uses and no more: text frames,
masked as a client must, and the three lengths a frame can state.

A machine with no browser skips these tests, and says so. Set
``PY1815_REQUIRE_BROWSER=1`` where a skip would be a failure nobody noticed.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import AsyncIterator
from typing import Any

import pytest

BROWSER_VARIABLE = "PY1815_BROWSER"
REQUIRE_VARIABLE = "PY1815_REQUIRE_BROWSER"

_NAMES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "msedge",
    "microsoft-edge",
)
_PLACES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


def find_browser() -> str | None:
    """A browser that speaks the DevTools protocol, or None if there is none."""
    named = os.environ.get(BROWSER_VARIABLE)
    if named:
        return named
    for name in _NAMES:
        found = shutil.which(name)
        if found:
            return found
    for place in _PLACES:
        if pathlib.Path(place).is_file():
            return place
    return None


def unavailable(reason: str) -> None:
    """Skip, or fail where a browser was promised."""
    if os.environ.get(REQUIRE_VARIABLE):
        pytest.fail(f"{REQUIRE_VARIABLE} is set, and {reason}")
    pytest.skip(reason)


class _WebSocket:
    """A WebSocket client: as much of RFC 6455 as a DevTools conversation uses."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    @classmethod
    async def connect(cls, url: str) -> _WebSocket:
        assert url.startswith("ws://")
        address, _, path = url[len("ws://") :].partition("/")
        host, _, port = address.partition(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        key = base64.b64encode(os.urandom(16)).decode()
        writer.write(
            (
                f"GET /{path} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"the browser refused the connection: {head[:80]!r}")
        return cls(reader, writer)

    async def send(self, text: str) -> None:
        payload = text.encode()
        head = bytearray([0x81])
        if len(payload) < 126:
            head.append(0x80 | len(payload))
        elif len(payload) < 1 << 16:
            head.append(0x80 | 126)
            head += struct.pack(">H", len(payload))
        else:
            head.append(0x80 | 127)
            head += struct.pack(">Q", len(payload))
        mask = os.urandom(4)
        masked = bytes(octet ^ mask[position % 4] for position, octet in enumerate(payload))
        self._writer.write(bytes(head) + mask + masked)
        await self._writer.drain()

    async def receive(self) -> str:
        message = bytearray()
        while True:
            first, second = await self._reader.readexactly(2)
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack(">H", await self._reader.readexactly(2))
            elif length == 127:
                (length,) = struct.unpack(">Q", await self._reader.readexactly(8))
            payload = await self._reader.readexactly(length)
            opcode = first & 0x0F
            if opcode == 0x8:
                raise ConnectionError("the browser closed the connection")
            if opcode == 0x9:
                continue  # A ping. This conversation is short enough not to answer.
            if opcode in (0x0, 0x1):
                message += payload
                if first & 0x80:
                    return message.decode()

    def close(self) -> None:
        self._writer.close()


class Page:
    """One page of the browser, and what a test asks of it."""

    def __init__(self, socket: _WebSocket) -> None:
        self._socket = socket
        self._next = 0
        #: Exceptions the page's own script threw.
        self.errors: list[str] = []
        #: The URL of every request the page made.
        self.requests: list[str] = []

    async def call(self, method: str, **params: Any) -> dict[str, Any]:
        self._next += 1
        identifier = self._next
        await self._socket.send(json.dumps({"id": identifier, "method": method, "params": params}))
        while True:
            message = json.loads(await self._socket.receive())
            if message.get("method") == "Runtime.exceptionThrown":
                details = message["params"]["exceptionDetails"]
                described = details.get("exception", {}).get("description", "")
                self.errors.append(f"{details.get('text', '')} {described}".strip())
            elif message.get("method") == "Network.requestWillBeSent":
                self.requests.append(message["params"]["request"]["url"])
            if message.get("id") == identifier:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return dict(message.get("result", {}))

    async def start(self) -> None:
        for domain in ("Page", "Runtime", "Network"):
            await self.call(f"{domain}.enable")
        # A page in a window nobody is looking at is sent no focus events.
        await self.call("Emulation.setFocusEmulationEnabled", enabled=True)
        await self.call(
            "Emulation.setDeviceMetricsOverride",
            width=1500,
            height=950,
            deviceScaleFactor=1,
            mobile=False,
        )

    async def goto(self, url: str) -> None:
        await self.call("Page.navigate", url=url)

    async def evaluate(self, expression: str) -> Any:
        """Run an expression in the page and return its value, which must be JSON."""
        result = await self.call(
            "Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True
        )
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            described = details.get("exception", {}).get("description", details.get("text"))
            raise AssertionError(f"the page could not evaluate {expression!r}: {described}")
        return result.get("result", {}).get("value")

    async def wait_for(self, expression: str, *, timeout: float = 20.0) -> Any:
        """Wait until an expression is truthy in the page, and return its value."""
        async with asyncio.timeout(timeout):
            while True:
                value = await self.evaluate(expression)
                if value:
                    return value
                await asyncio.sleep(0.1)

    async def text(self, selector: str) -> str:
        return str(await self.evaluate(f"document.querySelector({selector!r}).textContent"))

    async def click(self, selector: str) -> None:
        await self.evaluate(f"document.querySelector({selector!r}).click()")

    async def count(self, selector: str) -> int:
        return int(await self.evaluate(f"document.querySelectorAll({selector!r}).length"))


@contextlib.asynccontextmanager
async def open_page() -> AsyncIterator[Page]:
    """A page in a headless browser, closed and cleaned up afterwards."""
    browser = find_browser()
    if browser is None:
        unavailable("no browser was found to test the console in")
    assert browser is not None
    with tempfile.TemporaryDirectory(
        prefix="py1815-browser-", ignore_cleanup_errors=True
    ) as profile:
        process = subprocess.Popen(
            [
                browser,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                # A hosted runner does not let the browser build its sandbox, and
                # the only page loaded is this suite's own, from this machine.
                "--no-sandbox",
                "--remote-debugging-port=0",
                f"--user-data-dir={profile}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        socket: _WebSocket | None = None
        try:
            # The browser writes the port it chose to a file in its profile.
            chosen = pathlib.Path(profile) / "DevToolsActivePort"
            try:
                async with asyncio.timeout(30):
                    while not chosen.is_file() or not chosen.read_text().strip():
                        if process.poll() is not None:
                            raise OSError(f"it exited with status {process.returncode}")
                        await asyncio.sleep(0.1)
                    port = int(chosen.read_text().splitlines()[0])
                    while True:
                        try:
                            with urllib.request.urlopen(
                                f"http://127.0.0.1:{port}/json/list", timeout=5
                            ) as listed:
                                targets = json.load(listed)
                            pages = [target for target in targets if target["type"] == "page"]
                            if pages:
                                break
                        except OSError:
                            pass
                        await asyncio.sleep(0.1)
                socket = await _WebSocket.connect(pages[0]["webSocketDebuggerUrl"])
            except (OSError, TimeoutError) as error:
                unavailable(f"the browser at {browser} could not be started: {error}")
            assert socket is not None
            page = Page(socket)
            await page.start()
            yield page
        finally:
            if socket is not None:
                socket.close()
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
            if process.poll() is None:
                process.kill()
            # Give the browser's children a moment to let go of the profile,
            # which on Windows cannot be removed while they hold it.
            if sys.platform == "win32":
                await asyncio.sleep(0.5)
