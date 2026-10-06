"""The master as a service: its operations as JSON, over a line socket and over HTTP."""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815.decode import PointType
from py1815.master import cli
from py1815.master.service import (
    CONSOLE_DIRECTORY,
    HttpServer,
    LineServer,
    Service,
    flag_names,
)
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.server import OutstationServer


@pytest.fixture
def point_map():
    return load.resolve(for_reference_der(), Composition())


@pytest_asyncio.fixture
async def outstation(point_map):
    """A simulated DER listening on this machine."""
    simulation = der.build(point_map)
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield simulation, server
    finally:
        await server.stop()


@pytest_asyncio.fixture
async def service():
    made = Service()
    try:
        yield made
    finally:
        await made.close()


async def _ask(service: Service, op: str, outstation: str | None = None, **params):
    message = {"id": 7, "op": op, "params": params}
    if outstation is not None:
        message["outstation"] = outstation
    answer = await service.handle(message)
    assert answer["id"] == 7
    return answer


async def _added(service: Service, server: OutstationServer, **params) -> None:
    answer = await _ask(service, "add", name="lab", host="127.0.0.1", port=server.port, **params)
    assert answer["ok"], answer


class TestFlagNames:
    def test_each_point_type_reads_its_own_bits(self):
        assert flag_names(PointType.ANALOG_INPUT, 0x21) == ["ONLINE", "OVER_RANGE"]
        assert flag_names(PointType.COUNTER, 0x21) == ["ONLINE", "ROLLOVER"]
        assert flag_names(PointType.BINARY_INPUT, 0x21) == ["ONLINE", "CHATTER_FILTER"]

    def test_no_flag_octet_is_not_the_same_as_none_set(self):
        assert flag_names(PointType.ANALOG_INPUT, None) is None
        assert flag_names(PointType.ANALOG_INPUT, 0) == []


class TestOperations:
    @pytest.mark.asyncio
    async def test_an_outstation_is_added_scanned_and_read(self, service, outstation):
        simulation, server = outstation
        await _added(service, server)

        scan = (await _ask(service, "scan", "lab", kind="integrity"))["result"]
        assert scan["outcome"] == "complete" and scan["function"] == "READ"
        assert "DEVICE_RESTART" in scan["indications"]
        assert scan["object_count"] == len(scan["objects"]) > 0

        power = der.AI_METER_FIRST + 4
        read = (await _ask(service, "read", "lab", points={"ai": [power], "bi": "all"}))["result"]
        analog = next(o for o in read["objects"] if o["type"] == "ai")
        assert (analog["index"], analog["value"]) == (power, round(simulation.der.watts))
        assert analog["flags"] == ["ONLINE"]

        status = (await _ask(service, "status"))["result"]["outstations"]
        (lab,) = status
        assert lab["connected"] and lab["counts"] == {"complete": 2}
        assert lab["points"]["ai"] > 0 and lab["frames"] > 0

    @pytest.mark.asyncio
    async def test_values_come_from_the_store_with_no_traffic(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        await _ask(service, "scan", "lab", kind="class0")
        frames = (await _ask(service, "status"))["result"]["outstations"][0]["frames"]

        values = (await _ask(service, "values", "lab", types=["ai", "bi"]))["result"]["points"]

        assert set(values) == {"ai", "bi"} and values["ai"]
        first = values["ai"][0]
        assert {"index", "name", "value", "flags", "from_event", "age"} <= set(first)
        assert (await _ask(service, "status"))["result"]["outstations"][0]["frames"] == frames

    @pytest.mark.asyncio
    async def test_points_take_names_from_whoever_knows_the_map(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        service.set_names("lab", {PointType.BINARY_INPUT: {0: "The first one"}})
        scan = (await _ask(service, "read", "lab", points={"bi": [0, 1]}))["result"]
        assert [o["name"] for o in scan["objects"]] == ["The first one", None]

    @pytest.mark.asyncio
    async def test_a_profile_is_the_whole_map_and_not_only_what_was_reported(
        self, service, outstation, point_map
    ):
        """So a caller can see which of the profile's points an outstation never reports."""
        simulation, server = outstation
        await _added(service, server)
        assert (await _ask(service, "profile", "lab"))["result"] == {
            "version": None,
            "points": None,
        }
        assert (await _ask(service, "status"))["result"]["outstations"][0]["profile"] is None

        service.set_profile("lab", point_map)

        profile = (await _ask(service, "profile", "lab"))["result"]["points"]
        counts = (await _ask(service, "status"))["result"]["outstations"][0]["profile"]
        assert counts == {kind: len(points) for kind, points in profile.items()}
        in_map = sum(1 for kind, _ in point_map.points if kind is Kind.AI)
        assert counts["ai"] == in_map >= len(simulation.outstation.served(Kind.AI))
        assert counts["counter"] == counts["frozen"], "a frozen counter is its counter, frozen"
        first = profile["ai"][0]
        assert set(first) == {"index", "name", "mandatory", "section"}
        assert [point["index"] for point in profile["ai"]] == sorted(
            point["index"] for point in profile["ai"]
        )
        for kind, name in ((Kind.AI, "ai"), (Kind.BI, "bi")):
            required = {
                index for (k, index), p in point_map.points.items() if k is kind and p.mandatory
            }
            assert {point["index"] for point in profile[name] if point["mandatory"]} == required

    @pytest.mark.asyncio
    async def test_a_profile_names_the_points_that_are_reported(
        self, service, outstation, point_map
    ):
        _, server = outstation
        await _added(service, server)
        service.set_profile("lab", point_map)
        scan = (await _ask(service, "scan", "lab", kind="class0"))["result"]
        named = [o for o in scan["objects"] if o["type"] is not None]
        assert named and all(o["name"] for o in named)
        expected = point_map.point(Kind.BI, 0).name
        assert next(o for o in named if o["type"] == "bi" and o["index"] == 0)["name"] == expected

    @pytest.mark.asyncio
    async def test_events_are_kept_and_can_be_cleared(self, service, outstation):
        simulation, server = outstation
        await _added(service, server)
        await _ask(service, "scan", "lab", kind="events")
        simulation.advance(5.0)
        await _ask(service, "scan", "lab", kind="events")

        events = (await _ask(service, "events", "lab"))["result"]
        assert events["total"] > 0 and all(event["event"] for event in events["events"])

        assert (await _ask(service, "clear", "lab", what="events"))["ok"]
        assert (await _ask(service, "events", "lab"))["result"]["total"] == 0

    @pytest.mark.asyncio
    async def test_any_request_by_function_name_and_octets(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        answer = (await _ask(service, "request", "lab", function="delay_measure"))["result"]
        assert answer["outcome"] == "complete" and answer["request"] == "c017"
        refused = (await _ask(service, "request", "lab", function="READ", body="6e0006"))["result"]
        assert "OBJECT_UNKNOWN" in refused["indications"]

    @pytest.mark.asyncio
    async def test_unsolicited_reporting_is_asked_for_by_class(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        # This outstation was not built to send them, and says so.
        answer = (await _ask(service, "enable_unsolicited", "lab", classes=[1, 2]))["result"]
        assert answer["function"] == "ENABLE_UNSOLICITED"
        assert answer["request"].endswith("3c02063c0306")
        assert "FUNC_NOT_SUPPORTED" in answer["indications"]

    @pytest.mark.asyncio
    async def test_the_trace_is_read_and_cleared(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        await _ask(service, "scan", "lab", kind="class1")

        frames = (await _ask(service, "trace", "lab"))["result"]["frames"]
        sent, received = frames[0], frames[1]
        assert sent["direction"] == "tx" and sent["summary"] == "READ seq 0: class 1"
        assert received["direction"] == "rx" and received["application"]["function"] == "RESPONSE"
        assert bytes.fromhex(sent["octets"])[:2] == b"\x05\x64"

        later = (await _ask(service, "trace", "lab", after=frames[-1]["id"]))["result"]["frames"]
        assert later == []
        assert (await _ask(service, "clear", "lab"))["result"] == {"cleared": "trace"}
        assert (await _ask(service, "trace", "lab"))["result"]["frames"] == []

    @pytest.mark.asyncio
    async def test_a_scan_is_repeated_until_told_to_stop(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        answer = await _ask(service, "repeat", "lab", kind="class0", interval=0.05)
        assert answer["result"] == {"repeat": {"class0": 0.05}}

        async def answered() -> int:
            status = await _ask(service, "status")
            return status["result"]["outstations"][0]["counts"].get("complete", 0)

        async with asyncio.timeout(5):
            while await answered() < 3:
                await asyncio.sleep(0.02)

        assert (await _ask(service, "repeat", "lab", kind="class0", interval=None))["result"] == {
            "repeat": {}
        }
        await asyncio.sleep(0.1)
        settled = await answered()
        await asyncio.sleep(0.2)
        assert await answered() == settled

    @pytest.mark.asyncio
    async def test_scans_given_when_adding_start_with_the_connection(self, service, outstation):
        _, server = outstation
        await _added(service, server, event_interval=0.05)
        async with asyncio.timeout(5):
            while True:
                status = (await _ask(service, "status"))["result"]["outstations"][0]
                if status["counts"].get("complete", 0) >= 2:
                    break
                await asyncio.sleep(0.02)
        assert status["repeat"] == {"events": 0.05}

    @pytest.mark.asyncio
    async def test_output_status_is_read_as_often_as_the_integrity_poll(self, service, outstation):
        """An integrity poll does not return it, so one repeated alone leaves the outputs unread."""
        simulation, server = outstation
        await _added(service, server, integrity_interval=30)

        async with asyncio.timeout(5):
            while True:
                (lab,) = (await _ask(service, "status"))["result"]["outstations"]
                if lab["points"]["ao"] and lab["points"]["bo"]:
                    break
                await asyncio.sleep(0.02)

        assert lab["repeat"] == {"integrity": 30.0, "outputs": 30.0}
        assert lab["points"]["ao"] == len(simulation.outstation.served(Kind.AO))
        assert lab["points"]["bo"] == len(simulation.outstation.served(Kind.BO))

    @pytest.mark.asyncio
    async def test_unless_the_caller_says_how_often_or_not_at_all(self, service, outstation):
        _, server = outstation
        await _added(service, server, integrity_interval=30, output_interval=7)
        (lab,) = (await _ask(service, "status"))["result"]["outstations"]
        assert lab["repeat"] == {"integrity": 30.0, "outputs": 7.0}
        await _ask(service, "remove", "lab")

        await _added(service, server, integrity_interval=30, output_interval=None)
        (lab,) = (await _ask(service, "status"))["result"]["outstations"]
        assert lab["repeat"] == {"integrity": 30.0}

    @pytest.mark.asyncio
    async def test_nothing_is_repeated_for_an_outstation_added_with_no_interval(
        self, service, outstation
    ):
        _, server = outstation
        await _added(service, server)
        (lab,) = (await _ask(service, "status"))["result"]["outstations"]
        assert lab["repeat"] == {} and lab["counts"] == {}

    @pytest.mark.asyncio
    async def test_disconnect_connect_and_remove(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        assert not (await _ask(service, "disconnect", "lab"))["result"]["connected"]
        refused = await _ask(service, "scan", "lab", kind="class0")
        assert not refused["ok"] and refused["error"]["kind"] == "connection"
        assert (await _ask(service, "connect", "lab"))["result"]["connected"]
        assert (await _ask(service, "scan", "lab", kind="class0"))["ok"]
        assert (await _ask(service, "remove", "lab"))["result"] == {"removed": "lab"}
        assert (await _ask(service, "status"))["result"] == {"outstations": []}


class TestWhatGoesWrongIsAnAnswer:
    """``handle`` never raises: a script reads the reason from the response."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("message", "says"),
        [
            ("not an object", "a message is a JSON object"),
            ({"op": "explode"}, "'explode' is not an operation"),
            ({"op": "scan"}, "needs an outstation"),
            ({"op": "scan", "outstation": "nobody"}, "no outstation named 'nobody'"),
            ({"op": "add", "params": {"host": "127.0.0.1"}}, "added with a name"),
            ({"op": "add", "params": {"name": "x"}}, "added with a host"),
            ({"op": "status", "params": [1, 2]}, "params is a JSON object"),
        ],
    )
    async def test_a_message_that_cannot_be_acted_on(self, service, message, says):
        answer = await service.handle(message)
        assert not answer["ok"] and answer["error"]["kind"] == "request"
        assert says in answer["error"]["message"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params", "says"),
        [
            ("scan", {"kind": "class9"}, "'class9' is not a scan"),
            ("read", {"points": {}}, "names points"),
            ("read", {"points": {"zz": [1]}}, "'zz' is not a point type"),
            ("values", {"types": ["zz"]}, "'zz' is not a point type"),
            ("request", {"function": "NOPE"}, "'NOPE' is not a function code"),
            ("request", {"function": "READ", "body": "xyz"}, "hexadecimal"),
            ("enable_unsolicited", {"classes": [0]}, "by event class"),
            ("repeat", {"kind": "class0", "interval": 0}, "not a wait between scans"),
            ("clear", {"what": "everything"}, "the trace or the events"),
        ],
    )
    async def test_an_operation_given_the_wrong_things(self, service, outstation, op, params, says):
        _, server = outstation
        await _added(service, server)
        answer = await _ask(service, op, "lab", **params)
        assert not answer["ok"] and answer["error"]["kind"] == "request"
        assert says in answer["error"]["message"]

    @pytest.mark.asyncio
    async def test_an_outstation_that_cannot_be_reached_is_added_and_says_so(self, service):
        closed = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
        port = closed.sockets[0].getsockname()[1]
        closed.close()
        await closed.wait_closed()

        answer = await _ask(service, "add", name="lab", host="127.0.0.1", port=port)

        assert not answer["ok"] and answer["error"]["kind"] == "connection"
        (lab,) = (await _ask(service, "status"))["result"]["outstations"]
        assert lab["name"] == "lab" and not lab["connected"]

    @pytest.mark.asyncio
    async def test_a_name_is_used_once(self, service, outstation):
        _, server = outstation
        await _added(service, server)
        again = await _ask(service, "add", name="lab", host="127.0.0.1", port=server.port)
        assert not again["ok"] and "already been added" in again["error"]["message"]


class TestWhatHappensUnasked:
    @pytest.mark.asyncio
    async def test_a_subscriber_is_told_of_frames_exchanges_and_connections(
        self, service, outstation
    ):
        _, server = outstation
        queue = service.subscribe()
        await _added(service, server)
        await _ask(service, "scan", "lab", kind="class0")
        await _ask(service, "disconnect", "lab")

        seen = []
        while not queue.empty():
            seen.append(queue.get_nowait())
        kinds = [event["event"] for event in seen]
        assert kinds[0] == "outstations"
        assert {"connection", "frame", "exchange"} <= set(kinds)
        exchange = next(event for event in seen if event["event"] == "exchange")
        assert exchange["outstation"] == "lab" and exchange["exchange"]["outcome"] == "complete"
        connections = [event["connected"] for event in seen if event["event"] == "connection"]
        assert connections[0] is True and connections[-1] is False

    @pytest.mark.asyncio
    async def test_one_who_unsubscribed_is_told_nothing_more(self, service, outstation):
        _, server = outstation
        queue = service.subscribe()
        service.unsubscribe(queue)
        await _added(service, server)
        assert queue.empty()


class TestTheLineService:
    @pytest.mark.asyncio
    async def test_a_request_is_a_line_and_so_is_its_answer(self, service, outstation):
        _, server = outstation
        lines = LineServer(service)
        await lines.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", lines.port)

        async def ask(message) -> dict:
            writer.write(json.dumps(message).encode() + b"\n")
            await writer.drain()
            return json.loads(await reader.readline())

        try:
            added = await ask(
                {
                    "id": "a",
                    "op": "add",
                    "params": {"name": "lab", "host": "127.0.0.1", "port": server.port},
                }
            )
            assert added["id"] == "a" and added["ok"]
            scan = await ask(
                {"id": 2, "op": "scan", "outstation": "lab", "params": {"kind": "class0"}}
            )
            assert scan["id"] == 2 and scan["result"]["outcome"] == "complete"

            writer.write(b"this is not json\n")
            await writer.drain()
            bad = json.loads(await reader.readline())
            assert not bad["ok"] and "one JSON object" in bad["error"]["message"]
        finally:
            writer.close()
            await lines.stop()

    @pytest.mark.asyncio
    async def test_a_connection_that_subscribes_is_sent_what_happens(self, service, outstation):
        _, server = outstation
        lines = LineServer(service)
        await lines.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", lines.port)
        try:
            writer.write(b'{"id":1,"op":"subscribe"}\n')
            await writer.drain()
            assert json.loads(await reader.readline())["result"] == {"subscribed": True}
            await _added(service, server)
            async with asyncio.timeout(5):
                event = json.loads(await reader.readline())
            assert event == {"event": "outstations"}
        finally:
            writer.close()
            await lines.stop()

    def test_it_listens_on_this_machine_only(self, service):
        with pytest.raises(ValueError, match="this machine only"):
            LineServer(service, bind="0.0.0.0:0")


async def _http(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """One HTTP request over a plain socket, as a browser would send it."""
    sent = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    if body:
        sent["Content-Length"] = str(len(body))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in sent.items())
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(head.encode() + b"\r\n" + body)
        await writer.drain()
        raw = await reader.read()
    finally:
        writer.close()
    top, _, content = raw.partition(b"\r\n\r\n")
    lines = top.decode().split("\r\n")
    received = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split(" ")[1]), received, content


JSON = {"Content-Type": "application/json"}


class TestOverHttp:
    @pytest_asyncio.fixture
    async def http(self, service):
        server = HttpServer(service, bind="127.0.0.1:0")
        await server.start()
        try:
            yield server
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_the_console_is_served(self, http):
        status, headers, body = await _http(http.port, "GET", "/")
        assert status == 200 and headers["Content-Type"].startswith("text/html")
        assert b"<title>Satori DNP3 Master</title>" in body
        for name in ("console.js", "console.css", "satori.png"):
            status, _, content = await _http(http.port, "GET", f"/{name}")
            assert status == 200 and content == (CONSOLE_DIRECTORY / name).read_bytes()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/nothing.html", "/../service.py", "/..%2fservice.py"])
    async def test_only_the_consoles_own_files_are(self, http, path):
        status, _, _ = await _http(http.port, "GET", path)
        assert status == 404

    @pytest.mark.asyncio
    async def test_a_message_is_posted_and_its_answer_returned(self, http):
        body = json.dumps({"id": 3, "op": "status"}).encode()
        status, headers, content = await _http(http.port, "POST", "/api", body=body, headers=JSON)
        assert status == 200 and headers["Content-Type"] == "application/json"
        assert json.loads(content) == {"id": 3, "ok": True, "result": {"outstations": []}}

    @pytest.mark.asyncio
    async def test_a_request_from_another_site_is_refused(self, http):
        """A browser will carry a request from any page to a local port."""
        body = json.dumps({"op": "status"}).encode()
        elsewhere = {**JSON, "Origin": "http://elsewhere.example"}
        status, _, _ = await _http(http.port, "POST", "/api", body=body, headers=elsewhere)
        assert status == 403
        here = {**JSON, "Origin": f"http://127.0.0.1:{http.port}"}
        status, _, _ = await _http(http.port, "POST", "/api", body=body, headers=here)
        assert status == 200

    @pytest.mark.asyncio
    async def test_a_message_not_sent_as_json_is_refused(self, http):
        """The content type a page elsewhere may send without asking is not JSON."""
        body = json.dumps({"op": "status"}).encode()
        plain = {"Content-Type": "text/plain"}
        status, _, _ = await _http(http.port, "POST", "/api", body=body, headers=plain)
        assert status == 400

    @pytest.mark.asyncio
    async def test_a_name_that_is_not_this_machine_is_refused(self, http):
        status, _, _ = await _http(http.port, "GET", "/", headers={"Host": "elsewhere.example"})
        assert status == 403

    @pytest.mark.asyncio
    async def test_the_service_is_asked_with_post(self, http):
        status, _, _ = await _http(http.port, "GET", "/api")
        assert status == 405

    @pytest.mark.asyncio
    async def test_what_happens_arrives_as_server_sent_events(self, http, service):
        reader, writer = await asyncio.open_connection("127.0.0.1", http.port)
        try:
            writer.write(f"GET /events HTTP/1.1\r\nHost: 127.0.0.1:{http.port}\r\n\r\n".encode())
            await writer.drain()
            async with asyncio.timeout(5):
                head = await reader.readuntil(b"\r\n\r\n")
                assert b"text/event-stream" in head
                assert await reader.readuntil(b"\n\n") == b": connected\n\n"
                service.publish({"event": "outstations"})
                assert await reader.readuntil(b"\n\n") == b'data: {"event":"outstations"}\n\n'
        finally:
            writer.close()


class TestListeningToOtherMachines:
    def test_it_needs_a_token(self, service):
        with pytest.raises(ValueError, match="needs a token"):
            HttpServer(service, bind="0.0.0.0:0")

    @pytest.mark.asyncio
    async def test_and_then_every_request_needs_it(self, service):
        server = HttpServer(service, bind="127.0.0.1:0", token="s3cret")
        await server.start()
        try:
            status, _, _ = await _http(server.port, "GET", "/")
            assert status == 401
            status, _, _ = await _http(server.port, "GET", "/?token=wrong")
            assert status == 401
            status, _, _ = await _http(server.port, "GET", "/?token=s3cret")
            assert status == 200
            bearer = {**JSON, "Authorization": "Bearer s3cret"}
            body = json.dumps({"op": "status"}).encode()
            status, _, _ = await _http(server.port, "POST", "/api", body=body, headers=bearer)
            assert status == 200
            assert server.url.endswith("/?token=s3cret")
        finally:
            await server.stop()


class TestTheCommand:
    @pytest.mark.asyncio
    async def test_the_demonstration_adds_a_simulated_der_with_its_points_named(
        self, service, point_map
    ):
        demo = cli.Demo(service, point_map, tick=0.05)
        await demo.start()
        try:
            (added,) = (await _ask(service, "status"))["result"]["outstations"]
            assert added["name"] == cli.DEMO_NAME and added["connected"] and added["named"]
            assert added["repeat"] == {"integrity": 30.0, "events": 2.0, "outputs": 30.0}
            assert added["profile"]["ai"] == sum(
                1 for kind, _ in point_map.points if kind is Kind.AI
            )
            scan = (await _ask(service, "scan", cli.DEMO_NAME, kind="class0"))["result"]
            assert all(o["name"] for o in scan["objects"] if o["type"] is not None)
        finally:
            await demo.stop()

    def test_output_status_is_read_with_the_integrity_poll_unless_told_otherwise(self):
        parser = cli._parser()
        assert parser.parse_args(["serve"]).output_interval is None
        assert parser.parse_args(["serve", "--output-interval", "0"]).output_interval == 0
        assert parser.parse_args(["serve", "--output-interval", "5"]).output_interval == 5

    def test_an_outstation_is_named_on_the_command_line_as_name_host_port(self):
        args = cli._parser().parse_args(["serve", "--outstation", "lab=10.0.0.5:20000"])
        assert args.outstation == [("lab", "10.0.0.5", 20000)]
        with pytest.raises(SystemExit):
            cli._parser().parse_args(["serve", "--outstation", "lab"])

    def test_outstations_can_be_said_to_be_profile_devices(self, tmp_path, capsys):
        args = cli._parser().parse_args(["serve", "--profile", "--tables", "x.json"])
        assert args.profile and args.tables == "x.json"
        assert not cli._parser().parse_args(["console"]).profile
        missing = tmp_path / "none.json"
        assert cli.main(["serve", "--profile", "--tables", str(missing)]) == 1
        assert capsys.readouterr().err.strip()

    def test_a_demonstration_with_no_tables_says_how_to_get_them(self, tmp_path, capsys):
        missing = tmp_path / "none.json"
        assert cli.main(["console", "--demo", "--tables", str(missing)]) == 1
        assert capsys.readouterr().err.strip()

    def test_listening_to_other_machines_without_a_token_is_refused(self, capsys):
        assert cli.main(["console", "--bind", "0.0.0.0:0"]) == 2
        assert "needs a token" in capsys.readouterr().err
