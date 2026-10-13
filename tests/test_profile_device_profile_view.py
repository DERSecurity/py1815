"""The Device Profile reader and its page.

The reader takes any Device Profile XML and lays it out as facts, sections
and tables. These tests give it small documents written here and hold the
model to the exact labels and cells; give it the document this library builds
for the synthetic tables and hold the model to the outstation that document
describes; and give it input no reader should accept.
"""

from __future__ import annotations

import datetime
import html
import json
import re
from typing import ClassVar
from xml.etree import ElementTree

import pytest
from profile_fixtures import for_reference_der, small, units

from py1815.profile import cli, der, device_profile, load
from py1815.profile import device_profile_view as view
from py1815.profile.binding import Binding
from py1815.profile.device_profile_view import DeviceProfileError, Document, Fact, Section, Table
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation

NAMESPACE = "http://example.test/profile"


def profile(body: str, namespace: str = NAMESPACE) -> str:
    """Return a Device Profile document around some XML, in a namespace."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<DNP3DeviceProfileDocument xmlns="{namespace}">{body}</DNP3DeviceProfileDocument>'
    )


def setting(name: str, **parts: str) -> str:
    """Return one setting of the link configuration, with the parts given."""
    inner = "".join(f"<{part}>{content}</{part}>" for part, content in parts.items())
    return profile(
        "<referenceDevice><configuration><linkConfig>"
        f"<{name}>{inner}</{name}>"
        "</linkConfig></configuration></referenceDevice>"
    )


def table(document: Document, section: str, title: str) -> Table:
    """Return one table of a document, by its section and its title."""
    (found,) = [part for part in document.sections if part.title == section]
    (wanted,) = [each for each in found.tables if each.title == title]
    return wanted


def column(wanted: Table, name: str) -> list[str]:
    """Return one column of a table, a cell for each row."""
    position = wanted.columns.index(name)
    return [row[position] for row in wanted.rows]


def by_item(wanted: Table, name: str) -> dict[str, str]:
    """Return one row of a table of settings, as cells by column."""
    (row,) = [row for row in wanted.rows if row[0] == name]
    return dict(zip(wanted.columns, row, strict=True))


SMALL = """<?xml version="1.0" encoding="UTF-8"?>
<DNP3DeviceProfileDocument xmlns="http://example.test/profile" schemaVersion="2.12.00">
  <documentHeader>
    <documentName>Widget Profile</documentName>
    <documentDescription>What the widget does</documentDescription>
    <revisionHistory version="1">
      <date>2026-01-02</date>
      <author>A. Writer</author>
      <reason>First</reason>
    </revisionHistory>
    <revisionHistory version="2">
      <date>2026-02-03</date>
      <time>10:00:00</time>
      <author>A. Writer</author>
      <reason>Second</reason>
    </revisionHistory>
  </documentHeader>
  <referenceDevice>
    <configuration>
      <deviceConfig>
        <vendorName><currentValue><value>Example Co</value></currentValue></vendorName>
        <deviceName><currentValue><value>Widget 9</value></currentValue></deviceName>
      </deviceConfig>
      <linkConfig>
        <dataLinkAddress>
          <capabilities>
            <range><minimum>0</minimum><maximum>65519</maximum></range>
          </capabilities>
          <currentValue><value>1024</value></currentValue>
          <methods><software><name>Tool</name><version>2</version></software></methods>
        </dataLinkAddress>
        <maxReceivedFragmentSize>
          <capabilities>
            <configurableOther><description>Any size</description></configurableOther>
          </capabilities>
          <currentValue><value>2048</value></currentValue>
        </maxReceivedFragmentSize>
        <linkLayerConfirmTimeout>
          <capabilities><none/></capabilities>
          <currentValue><none/></currentValue>
        </linkLayerConfirmTimeout>
        <expectedSourceAddress/>
      </linkConfig>
    </configuration>
    <implementationTable>
      <table>
        <supportedVariation>
          <objectGroup>1</objectGroup>
          <variation>2</variation>
          <description>Binary Input - with flags</description>
          <request>
            <functionCode>1</functionCode>
            <qualifierCode>0</qualifierCode>
            <qualifierCode>6</qualifierCode>
          </request>
          <response><functionCode>129</functionCode><qualifierCode>0</qualifierCode></response>
        </supportedVariation>
        <supportedFunctionCode>
          <request><functionCode>23</functionCode></request>
        </supportedFunctionCode>
      </table>
    </implementationTable>
    <dataPointsList>
      <binaryInputPoints>
        <configuration><pointListDefinition><fixed/></pointListDefinition></configuration>
        <dataPoints>
          <binaryInput>
            <index>0</index>
            <name>Door</name>
            <changeEventClass>one</changeEventClass>
          </binaryInput>
          <binaryInput>
            <index>1</index>
            <name>Alarm</name>
            <description>Any alarm</description>
            <changeEventClass>two</changeEventClass>
            <nameState0>Clear</nameState0>
          </binaryInput>
        </dataPoints>
      </binaryInputPoints>
    </dataPointsList>
  </referenceDevice>
</DNP3DeviceProfileDocument>
"""

SMALL_MODEL = Document(
    title="Widget Profile",
    facts=(
        Fact("Schema version", "2.12.00"),
        Fact("Document name", "Widget Profile"),
        Fact("Document description", "What the widget does"),
        Fact("Vendor name", "Example Co"),
        Fact("Device name", "Widget 9"),
    ),
    sections=(
        Section(
            "Document header",
            (
                Table(
                    "Revision history",
                    ("Version", "Date", "Time", "Author", "Reason"),
                    (
                        ("1", "2026-01-02", "", "A. Writer", "First"),
                        ("2", "2026-02-03", "10:00:00", "A. Writer", "Second"),
                    ),
                ),
            ),
        ),
        Section(
            "Configuration",
            (
                Table(
                    "Device config",
                    ("Item", "Capabilities", "Current value"),
                    (("Vendor name", "", "Example Co"), ("Device name", "", "Widget 9")),
                ),
                Table(
                    "Link config",
                    ("Item", "Capabilities", "Current value", "Methods"),
                    (
                        (
                            "Data link address",
                            "0 to 65519",
                            "1024",
                            "Software (Name: Tool; Version: 2)",
                        ),
                        ("Max received fragment size", "Configurable other: Any size", "2048", ""),
                        ("Link layer confirm timeout", "None", "None", ""),
                        ("Expected source address", "", "", ""),
                    ),
                ),
            ),
        ),
        Section(
            "Implementation table",
            (
                Table(
                    "Supported variation",
                    (
                        "Object group",
                        "Variation",
                        "Description",
                        "Request function code",
                        "Request qualifier code",
                        "Response function code",
                        "Response qualifier code",
                    ),
                    (("1", "2", "Binary Input - with flags", "1", "0, 6", "129", "0"),),
                ),
                Table("Supported function code", ("Request function code",), (("23",),)),
            ),
        ),
        Section(
            "Data points list",
            (
                Table(
                    "Binary input points: Configuration",
                    ("Item", "Stated"),
                    (("Point list definition", "Fixed"),),
                ),
                Table(
                    "Binary input points",
                    ("Index", "Name", "Description", "Change event class", "Name state 0"),
                    (
                        ("0", "Door", "", "one", ""),
                        ("1", "Alarm", "Any alarm", "two", "Clear"),
                    ),
                ),
            ),
        ),
    ),
)


class TestASmallDocument:
    def test_it_reads_into_facts_sections_and_tables(self):
        assert view.read(SMALL) == SMALL_MODEL

    def test_a_value_the_document_does_not_state_is_an_empty_cell(self):
        document = view.read(SMALL)
        link = table(document, "Configuration", "Link config")
        assert by_item(link, "Expected source address") == {
            "Item": "Expected source address",
            "Capabilities": "",
            "Current value": "",
            "Methods": "",
        }
        points = table(document, "Data points list", "Binary input points")
        # The first point has no description and no state name: neither is made up.
        assert column(points, "Description") == ["", "Any alarm"]
        assert column(points, "Name state 0") == ["", "Clear"]

    def test_the_methods_column_is_there_only_when_a_setting_gives_its_methods(self):
        document = view.read(SMALL)
        assert "Methods" in table(document, "Configuration", "Link config").columns
        assert "Methods" not in table(document, "Configuration", "Device config").columns

    def test_a_property_only_some_records_carry_is_a_column_where_they_have_it(self):
        history = table(view.read(SMALL), "Document header", "Revision history")
        assert history.columns == ("Version", "Date", "Time", "Author", "Reason")

    def test_octets_are_decoded_as_the_document_declares(self):
        latin = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            "<DNP3DeviceProfileDocument><documentHeader>"
            "<documentName>Caf\u00e9 feeder</documentName>"
            "</documentHeader></DNP3DeviceProfileDocument>"
        ).encode("iso-8859-1")
        assert view.read(latin).title == "Caf\u00e9 feeder"

    def test_it_is_described_as_json(self):
        described = view.read(SMALL).describe()
        assert json.loads(json.dumps(described)) == described
        assert described["title"] == "Widget Profile"
        assert described["notice"] == view.NOTICE
        assert described["facts"][0] == {"label": "Schema version", "value": "2.12.00"}
        configuration = described["sections"][1]
        assert configuration["title"] == "Configuration"
        assert configuration["tables"][0] == {
            "title": "Device config",
            "columns": ["Item", "Capabilities", "Current value"],
            "rows": [["Vendor name", "", "Example Co"], ["Device name", "", "Widget 9"]],
        }

    def test_a_document_with_no_name_is_titled_by_its_device_and_then_by_what_it_is(self):
        device = profile(
            "<referenceDevice><configuration><deviceConfig>"
            "<deviceName><currentValue><value>Widget 9</value></currentValue></deviceName>"
            "</deviceConfig></configuration></referenceDevice>"
        )
        assert view.read(device).title == "Widget 9"
        assert view.read(profile("")).title == view.DEFAULT_TITLE


class TestLabels:
    @pytest.mark.parametrize(
        ("name", "label"),
        [
            ("maxReceivedFragmentSize", "Max received fragment size"),
            ("maxObjectsInCROBControlRequest", "Max objects in CROB control request"),
            ("outStation", "Outstation"),
            ("outStationConfig", "Outstation config"),
            ("timeoutStation", "Timeout station"),
            ("supportsDNP3ClockManagement", "Supports DNP3 clock management"),
            ("outstationSetsIIN14", "Outstation sets IIN14"),
            ("class0ResponseMode", "Class 0 response mode"),
            ("tcpListenPort", "TCP listen port"),
            ("ipAddress", "IP address"),
            ("dnpLANProcedure", "DNP LAN procedure"),
            ("vendor_name-2", "Vendor name 2"),
        ],
    )
    def test_an_element_name_is_made_readable_by_its_capitals_and_digits(self, name, label):
        link = table(
            view.read(setting(name, currentValue="<value>1</value>")),
            "Configuration",
            "Link config",
        )
        assert column(link, "Item") == [label]


class TestWhatASettingSays:
    @pytest.mark.parametrize(
        ("capabilities", "cell"),
        [
            ("<range><minimum>0</minimum><maximum>65519</maximum></range>", "0 to 65519"),
            (
                "<periodicallyRange><minimum>1</minimum><maximum>9</maximum></periodicallyRange>",
                "Periodically range: 1 to 9",
            ),
            ("<none/>", "None"),
            ("<fixed>292</fixed>", "Fixed: 292"),
            ("<withinSecondsOfIIN14>30</withinSecondsOfIIN14>", "Within seconds of IIN14: 30"),
            (
                "<configurableOther><description>Any size</description></configurableOther>",
                "Configurable other: Any size",
            ),
            ("<other><explanation>By hand</explanation></other>", "Other: By hand"),
            ("<never/><alwaysSingleAddress/>", "Never\nAlways single address"),
            (
                "<selectable>1200</selectable><selectable>9600</selectable>",
                "Selectable: 1200\nSelectable: 9600",
            ),
            (
                "<perClass><class1Value>10</class1Value><class2Value>20</class2Value></perClass>",
                "Per class (Class 1 value: 10; Class 2 value: 20)",
            ),
            ("<supported><yes/></supported><configurable/>", "Supported: Yes\nConfigurable"),
            ("<value>7</value>", "7"),
            # An empty value states nothing, and is not shown as the word "Value".
            ("<value/>", ""),
            ('<file access="read">log.txt</file>', "File: Access: read; log.txt"),
            ("<range><minimum>0</minimum></range>", "Range: Minimum: 0"),
        ],
    )
    def test_nested_values_are_flattened_into_text(self, capabilities, cell):
        document = view.read(setting("someSetting", capabilities=capabilities))
        link = table(document, "Configuration", "Link config")
        assert by_item(link, "Some setting")["Capabilities"] == cell

    def test_capabilities_and_current_value_are_columns_when_only_one_is_stated(self):
        document = view.read(setting("someSetting", currentValue="<value>7</value>"))
        link = table(document, "Configuration", "Link config")
        assert link == Table(
            "Link config", ("Item", "Capabilities", "Current value"), (("Some setting", "", "7"),)
        )


UNKNOWN = profile(
    "<referenceDevice>"
    "<configuration><linkConfig>"
    "<dataLinkAddress>"
    "<currentValue><value>7</value></currentValue>"
    "<vendorRemark>Set at the factory</vendorRemark>"
    "</dataLinkAddress>"
    "<keepAliveStyle>gentle</keepAliveStyle>"
    "</linkConfig></configuration>"
    "<vendorExtension><widgetSettings>"
    "<widgetCount>3</widgetCount><mode><fast/></mode>"
    "</widgetSettings></vendorExtension>"
    "</referenceDevice>"
    "<auxiliaryInfo><somethingElse>"
    "<detail>Kept</detail><more><deep>er</deep></more>"
    "</somethingElse></auxiliaryInfo>"
    "<issuedBy>Example Co</issuedBy>"
)


class TestWhatTheLayoutDoesNotRecognize:
    def test_an_unknown_element_in_a_setting_and_an_unknown_setting_are_kept(self):
        link = table(view.read(UNKNOWN), "Configuration", "Link config")
        assert link == Table(
            "Link config",
            ("Item", "Capabilities", "Current value", "Stated"),
            (
                ("Data link address", "", "7", "Vendor remark: Set at the factory"),
                ("Keep alive style", "", "", "gentle"),
            ),
        )

    def test_an_unknown_part_of_the_device_is_a_section_of_its_own(self):
        extension = table(view.read(UNKNOWN), "Vendor extension", "Widget settings")
        assert extension == Table(
            "Widget settings", ("Item", "Stated"), (("Widget count", "3"), ("Mode", "Fast"))
        )

    def test_an_unknown_part_of_the_document_is_a_section_under_its_own_name(self):
        other = table(view.read(UNKNOWN), "Auxiliary info: Something else", "")
        assert other == Table("", ("Item", "Stated"), (("Detail", "Kept"), ("More", "Deep: er")))

    def test_an_unknown_element_beside_the_header_is_a_fact(self):
        assert Fact("Issued by", "Example Co") in view.read(UNKNOWN).facts

    def test_an_attribute_and_text_beside_child_elements_are_kept(self):
        document = view.read(
            profile(
                '<referenceDevice><vendorExtension edition="3">Read this first'
                "<widget><count><exact>3</exact></count></widget>"
                "</vendorExtension></referenceDevice>"
            )
        )
        (section,) = document.sections
        assert section.tables[0] == Table(
            "",
            ("Item", "Stated"),
            (("Edition", "3"), ("Vendor extension", "Read this first")),
        )

    def test_every_text_and_every_name_in_a_document_reaches_the_model(self):
        """Nothing is dropped: each element's text is in a cell, a fact or a title."""
        for text in (SMALL, UNKNOWN):
            described = json.dumps(view.read(text).describe())
            root = ElementTree.fromstring(text)
            for element in root.iter():
                if element.text and element.text.strip():
                    assert json.dumps(element.text.strip())[1:-1] in described, element.tag


class TestAnotherNamespace:
    BODY = SMALL.split("?>", 1)[1]

    @pytest.mark.parametrize(
        "namespace",
        [
            "http://www.dnp3.org/DNP3/DeviceProfile/April2016",
            "urn:example:another-edition",
            "a namespace with spaces",
        ],
    )
    def test_a_document_in_another_namespace_reads_the_same(self, namespace):
        assert NAMESPACE in self.BODY
        assert view.read(self.BODY.replace(NAMESPACE, namespace)) == SMALL_MODEL

    def test_a_document_in_no_namespace_reads_the_same(self):
        assert view.read(self.BODY.replace(f' xmlns="{NAMESPACE}"', "")) == SMALL_MODEL

    def test_text_a_part_of_the_document_carries_beside_its_elements_is_kept(self):
        document = view.read(
            profile(
                "<vendorExtension>Read this first"
                "<settings><a><currentValue><value>1</value></currentValue></a></settings>"
                "</vendorExtension>"
            )
        )
        assert Fact("Vendor extension", "Read this first") in document.facts
        assert [section.title for section in document.sections] == ["Vendor extension: Settings"]

    def test_the_title_is_the_headers_name_and_not_a_fact_with_the_same_label(self):
        # An attribute a vendor put on the root has the label the header's
        # name has. It is shown, and it is not the title.
        text = (
            '<DNP3DeviceProfileDocument documentName="An extension value">'
            "<documentHeader><documentName>The real name</documentName></documentHeader>"
            "</DNP3DeviceProfileDocument>"
        )
        document = view.read(text)
        assert document.title == "The real name"
        assert Fact("Document name", "An extension value") in document.facts

    def test_a_document_with_no_name_of_its_own_takes_a_fact_with_that_label(self):
        text = '<DNP3DeviceProfileDocument documentName="The only name given"/>'
        assert view.read(text).title == "The only name given"

    def test_two_attributes_with_one_local_name_are_both_kept(self):
        # Attributes of two namespaces can share a local name. Neither is lost.
        document = view.read(
            profile(
                '<referenceDevice><vendorExtension xmlns:a="urn:a" xmlns:b="urn:b" '
                'a:edition="one" b:edition="two">Read this first'
                "<widget><count><exact>3</exact></count></widget>"
                "</vendorExtension></referenceDevice>"
            )
        )
        rows = document.sections[0].tables[0].rows
        assert rows[:2] == (("Edition", "one"), ("Edition", "two"))

    def test_a_document_whose_elements_carry_a_prefix_reads_the_same(self):
        prefixed = re.sub(r"<(/?)([A-Za-z])", r"<\1p:\2", self.BODY).replace(
            f'xmlns="{NAMESPACE}"', f'xmlns:p="{NAMESPACE}"'
        )
        assert "<p:dataLinkAddress>" in prefixed
        assert view.read(prefixed) == SMALL_MODEL


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


def _built(simulation: der.Simulation, **session_options) -> tuple[str, Document]:
    session = simulation.outstation.session(**session_options)
    root = device_profile.build(
        simulation.outstation,
        session,
        device_profile.Identity(vendor="Example Co", device="EX-100", host="192.0.2.1", port=20000),
        today=datetime.date(2026, 1, 2),
    )
    text = device_profile.render(root)
    return text, view.read(text)


class TestTheDocumentThisLibraryBuilds:
    """Held to the outstation the document describes, and not to the reader."""

    TABLES: ClassVar[dict[Kind, str]] = {
        Kind.BI: "Binary input points",
        Kind.BO: "Binary output points",
        Kind.CTR: "Counter points",
        Kind.AI: "Analog input points",
        Kind.AO: "Analog output points",
    }

    @pytest.mark.parametrize("kind", list(Kind))
    def test_every_point_the_outstation_serves_is_a_row_of_its_table(self, simulation, kind):
        _, document = _built(simulation)
        points = table(document, "Data points list", self.TABLES[kind])
        served = simulation.outstation.served(kind)
        assert served
        assert column(points, "Index") == [str(point.index) for point in served]
        assert column(points, "Name") == [point.name for point in served]

    def test_a_points_properties_are_its_columns(self):
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        binding.read(Kind.AI, 2, lambda: 240.0)
        binding.read(Kind.CTR, 0, lambda: 1)
        binding.output(Kind.AO, 0)
        outstation = DerOutstation(load.resolve(small(), units(0)), binding, strict=False)
        text = device_profile.render(device_profile.build(outstation, outstation.session()))
        document = view.read(text)

        voltage = table(document, "Data points list", "Analog input points")
        assert by_item(voltage, "2") == {
            "Index": "2",
            "Name": "Voltage",
            "Change event class": "two",
            "Included in class 0 response": "always",
            "Min integer transmitted value": "0",
            "Max integer transmitted value": "6000",
            "Scale factor": "0.1",
            "Units": "x",
            "DNP data deadband": "0",
        }
        counter = table(document, "Data points list", "Counter points")
        assert by_item(counter, "0") == {
            "Index": "0",
            "Name": "Energy out",
            "Counters included in class 0": "always",
            "Counter event class": "none",
            "Frozen counter exists": "true",
            "Frozen counters included in class 0": "always",
            "Frozen counter event class": "three",
        }
        setpoint = table(document, "Data points list", "Analog output points")
        assert by_item(setpoint, "0")["Supported control operations"] == (
            "Support select operate, Support direct operate, Support direct operate no ack"
        )

    def test_the_configuration_is_the_sessions(self, simulation):
        _, document = _built(simulation, max_response=4096, select_timeout=7.0)
        facts = simulation.outstation.session(max_response=4096, select_timeout=7.0).facts

        link = table(document, "Configuration", "Link config")
        assert by_item(link, "Data link address") == {
            "Item": "Data link address",
            "Capabilities": "0 to 65519",
            "Current value": str(facts.outstation_address),
        }
        assert by_item(link, "Expected source address")["Current value"] == str(
            facts.master_address
        )
        application = table(document, "Configuration", "Appl config")
        assert by_item(application, "Max transmitted fragment size")["Current value"] == "4096"
        assert by_item(application, "Max received fragment size")["Current value"] == str(
            facts.max_request
        )
        outstation = table(document, "Configuration", "Outstation config")
        capacity = facts.event_capacity
        assert by_item(outstation, "Event buffer organization")["Current value"] == (
            f"Per class (Class 1 value: {capacity}; Class 2 value: {capacity}; "
            f"Class 3 value: {capacity})"
        )
        outputs = table(document, "Database", "Binary output group: Configuration")
        assert by_item(outputs, "Max time between select and operate")["Current value"] == "7"
        network = table(document, "Configuration", "Network config")
        assert by_item(network, "TCP listen port")["Current value"] == "20000"

    def test_the_header_facts_name_the_document_and_the_device(self, simulation):
        _, document = _built(simulation)
        assert document.title == "EX-100 Device Profile"
        stated = {fact.label: fact.value for fact in document.facts}
        assert stated["Schema version"] == device_profile.SCHEMA_VERSION
        assert stated["Vendor name"] == "Example Co"
        assert stated["Device name"] == "EX-100"
        history = table(document, "Document header", "Revision history")
        assert history.rows == (("1", "2026-01-02", "py1815", "Generated"),)

    @pytest.mark.parametrize("options", [{}, {"unsolicited": True}])
    def test_every_setting_the_document_holds_is_a_row(self, simulation, options):
        """Counted with another parser: one row for each setting, in the document's order."""
        text, document = _built(simulation, **options)
        root = ElementTree.fromstring(text.split("?>", 2)[2])
        space = {"d": device_profile.NAMESPACE}
        configuration = root.find("d:referenceDevice/d:configuration", space)
        assert len(configuration) > 5
        for part in configuration:
            name = part.tag.split("}")[1]
            title = name[0].upper() + re.sub(r"([A-Z])", r" \1", name[1:]).lower()
            rows = table(document, "Configuration", title).rows
            assert len(rows) == len(part) > 0, name
        database = root.find("d:referenceDevice/d:database", space)
        tables = {each.title: each for each in document.sections[2].tables}
        assert document.sections[2].title == "Database"
        assert len(tables) == len(database) == 5
        for group, laid_out in zip(database, tables.values(), strict=True):
            assert len(laid_out.rows) == len(group.find("d:configuration", space))

    def test_the_implementation_table_has_a_row_for_each_object_and_function_code(self, simulation):
        _, document = _built(simulation)
        listed = device_profile.implementation(
            simulation.outstation, simulation.outstation.session().facts
        )
        objects = table(document, "Implementation table", "Supported variation")
        assert [(row[0], row[1], row[2]) for row in objects.rows] == [
            (str(row.group), str(row.variation), row.description) for row in listed.rows
        ]
        first = listed.rows[1]
        assert first.request is not None and first.response is not None
        assert dict(zip(objects.columns, objects.rows[1], strict=True)) == {
            "Object group": str(first.group),
            "Variation": str(first.variation),
            "Description": first.description,
            "Request function code": str(first.request[0]),
            "Request qualifier code": ", ".join(map(str, first.request[1])),
            "Response function code": str(first.response[0]),
            "Response qualifier code": ", ".join(map(str, first.response[1])),
        }
        codes = table(document, "Implementation table", "Supported function code")
        assert column(codes, "Request function code") == [
            str(code) for code in listed.function_codes
        ]


BOMB = """<?xml version="1.0"?>
<!DOCTYPE DNP3DeviceProfileDocument [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
]>
<DNP3DeviceProfileDocument><documentHeader><documentName>&f;</documentName></documentHeader>
</DNP3DeviceProfileDocument>
"""


class TestWhatIsRefused:
    @pytest.mark.parametrize("text", ["", "not a document at all", "<a><b></a>", "{}"])
    def test_text_that_is_not_xml(self, text):
        with pytest.raises(DeviceProfileError, match=r"^the document is not XML: "):
            view.read(text)

    def test_xml_that_is_not_a_device_profile(self):
        with pytest.raises(DeviceProfileError) as refused:
            view.read('<?xml version="1.0"?><html><body>A page</body></html>')
        assert str(refused.value) == (
            "the document is not a Device Profile: its root element is html, "
            "not DNP3DeviceProfileDocument"
        )

    def test_a_document_that_defines_entities_to_expand_without_bound(self):
        with pytest.raises(DeviceProfileError, match="document type declaration"):
            view.read(BOMB)

    def test_a_document_that_names_something_to_fetch(self):
        external = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE DNP3DeviceProfileDocument SYSTEM "http://192.0.2.1/profile.dtd" [\n'
            '<!ENTITY secret SYSTEM "file:///etc/hostname">]>\n'
            "<DNP3DeviceProfileDocument><documentHeader>"
            "<documentName>&secret;</documentName>"
            "</documentHeader></DNP3DeviceProfileDocument>"
        )
        with pytest.raises(DeviceProfileError, match="document type declaration"):
            view.read(external)

    def test_a_document_type_with_nothing_in_it_is_refused_too(self):
        text = "<!DOCTYPE DNP3DeviceProfileDocument><DNP3DeviceProfileDocument/>"
        with pytest.raises(DeviceProfileError, match="document type declaration"):
            view.read(text)

    def test_the_words_of_a_declaration_inside_text_are_not_one(self):
        document = view.read(
            profile(
                "<documentHeader><documentName>About &lt;!DOCTYPE and <![CDATA[<!DOCTYPE x>]]>"
                "</documentName></documentHeader>"
            )
        )
        assert document.title == "About <!DOCTYPE and <!DOCTYPE x>"

    @pytest.mark.parametrize("kind", [str, bytes])
    def test_a_document_over_the_size_limit(self, kind):
        body = profile("<documentHeader/>") + " " * view.MAX_SIZE
        text = body if kind is str else body.encode()
        with pytest.raises(DeviceProfileError) as refused:
            view.read(text)
        assert str(refused.value) == (
            "the Device Profile document is larger than 8 MiB, the most that is read"
        )

    def test_a_document_at_the_size_limit_is_read(self):
        text = profile("<documentHeader/>")
        assert view.read(text + " " * (view.MAX_SIZE - len(text))).title == view.DEFAULT_TITLE

    def test_a_document_of_more_elements_than_the_limit(self, monkeypatch):
        monkeypatch.setattr(view, "MAX_ELEMENTS", 50)
        within = profile("<referenceDevice>" + "<a/>" * 48 + "</referenceDevice>")
        assert view.read(within).title == view.DEFAULT_TITLE
        with pytest.raises(DeviceProfileError, match="more than 50 elements"):
            view.read(profile("<referenceDevice>" + "<a/>" * 49 + "</referenceDevice>"))

    @staticmethod
    def _records(properties: list[list[str]]) -> str:
        """Return a document with one list of records, each carrying the properties named."""
        rows = "".join(
            "<row>" + "".join(f"<{name}>1</{name}>" for name in names) + "</row>"
            for names in properties
        )
        return profile(f"<referenceDevice><things>{rows}</things></referenceDevice>")

    def test_records_that_each_carry_a_property_of_their_own_are_refused(self):
        # A column for each property: a thousand records with a thousand
        # different properties would be a table of a million cells, from a
        # document of a few tens of kilobytes.
        text = self._records([[f"p{number}"] for number in range(1000)])
        assert len(text) < 64 * 1024
        with pytest.raises(DeviceProfileError, match="more than 200 columns"):
            view.read(text)

    def test_a_table_as_wide_as_the_limit_is_laid_out(self, monkeypatch):
        monkeypatch.setattr(view, "MAX_COLUMNS", 5)
        document = view.read(self._records([[f"p{number}"] for number in range(5)]))
        assert len(document.sections[0].tables[0].columns) == 5
        with pytest.raises(DeviceProfileError, match="more than 5 columns"):
            view.read(self._records([[f"p{number}"] for number in range(6)]))

    def test_tables_with_more_cells_between_them_than_the_limit_are_refused(self, monkeypatch):
        monkeypatch.setattr(view, "MAX_CELLS", 20)
        four_columns = ["a", "b", "c", "d"]
        document = view.read(self._records([four_columns] * 5))
        assert len(document.sections[0].tables[0].rows) == 5, "twenty cells are laid out"
        with pytest.raises(DeviceProfileError, match="more than 20 cells"):
            view.read(self._records([four_columns] * 6))

    def test_elements_nested_deeper_than_the_limit(self):
        def nested(depth: int) -> str:
            # The root is the first level.
            return profile("<a>" * (depth - 1) + "</a>" * (depth - 1))

        assert view.read(nested(view.MAX_DEPTH)).title == view.DEFAULT_TITLE
        with pytest.raises(DeviceProfileError, match=f"more than {view.MAX_DEPTH} deep"):
            view.read(nested(view.MAX_DEPTH + 1))
        with pytest.raises(DeviceProfileError, match=f"more than {view.MAX_DEPTH} deep"):
            view.read(nested(100_000))

    def test_a_refusal_is_a_value_error(self):
        """The service reports a ValueError as a request it could not act on."""
        assert issubclass(DeviceProfileError, ValueError)


HOSTILE = "<script>alert('x')</script> & \"quoted\" <img src=x onerror=alert(1)>"


def _hostile() -> str:
    escaped = HOSTILE.replace("&", "&amp;").replace("<", "&lt;")
    return profile(
        f"<documentHeader><documentName>{escaped}</documentName></documentHeader>"
        "<referenceDevice><dataPointsList><binaryInputPoints><dataPoints>"
        f"<binaryInput><index>0</index><name>{escaped}</name></binaryInput>"
        "</dataPoints></binaryInputPoints></dataPointsList></referenceDevice>"
    )


class TestThePage:
    def test_it_is_one_standalone_html_page_that_says_whose_layout_it_is(self):
        page = view.page(view.read(SMALL))
        assert page.startswith('<!doctype html>\n<html lang="en">')
        assert page.endswith("</html>\n")
        assert "<title>Widget Profile</title>" in page
        assert "<h1>Widget Profile</h1>" in page
        assert f'<p class="notice">{html.escape(view.NOTICE)}</p>' in page
        assert "py1815" in view.NOTICE and "not the DNP Users Group's" in view.NOTICE

    def test_every_fact_section_table_and_cell_is_on_the_page(self):
        page = view.page(view.read(SMALL))
        assert "<dt>Vendor name</dt><dd>Example Co</dd>" in page
        assert '<section id="section-2">\n<h2>Configuration</h2>\n<h3>Device config</h3>' in page
        assert '<li><a href="#section-2">Configuration</a></li>' in page
        heads = (
            '<thead><tr><th scope="col">Item</th><th scope="col">Capabilities</th>'
            '<th scope="col">Current value</th><th scope="col">Methods</th></tr></thead>'
        )
        assert heads in page
        assert (
            "<tr><td>Data link address</td><td>0 to 65519</td><td>1024</td>"
            "<td>Software (Name: Tool; Version: 2)</td></tr>"
        ) in page
        assert "<tr><td>Expected source address</td><td></td><td></td><td></td></tr>" in page
        assert page.count("<table") == sum(len(part.tables) for part in SMALL_MODEL.sections)

    def test_text_from_the_document_is_escaped(self):
        document = view.read(_hostile())
        assert document.title == HOSTILE
        points = table(document, "Data points list", "Binary input points")
        assert column(points, "Name") == [HOSTILE]

        page = view.page(document)

        escaped = (
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt; &amp; &quot;quoted&quot; "
            "&lt;img src=x onerror=alert(1)&gt;"
        )
        assert f"<td>{escaped}</td>" in page
        assert f"<title>{escaped}</title>" in page
        assert f"<h1>{escaped}</h1>" in page
        assert "<script" not in page and "<img" not in page

    @pytest.mark.parametrize("text", [SMALL, UNKNOWN])
    def test_it_runs_no_script_and_refers_to_nothing_outside_itself(self, text):
        page = view.page(view.read(text))
        for tag in ("script", "link", "img", "iframe", "object", "embed", "base", "form"):
            assert f"<{tag}" not in page.lower(), tag
        assert "@import" not in page and "url(" not in page
        assert not re.search(r"\s(src|action|on[a-z]+)\s*=", page)
        links = re.findall(r'href="([^"]*)"', page)
        assert links and all(link.startswith("#section-") for link in links)

    def test_it_carries_the_rules_that_make_it_print_cleanly(self):
        page = view.page(view.read(SMALL))
        style = page.split("<style>", 1)[1].split("</style>", 1)[0]
        assert re.search(r"@page\s*{\s*margin:", style)
        printed = style.split("@media print", 1)[1]
        # The headings of a table are repeated on each page it runs to.
        assert re.search(r"thead\s*{\s*display:\s*table-header-group", printed)
        # A row is not split across two pages, and a heading stays with its table.
        assert re.search(r"tr[^{]*{[^}]*break-inside:\s*avoid", printed)
        assert re.search(r"h2, h3\s*{[^}]*break-after:\s*avoid", printed)
        # What is only for the screen is not printed.
        assert re.search(r"\.contents\s*{\s*display:\s*none", printed)

    def test_a_table_of_many_columns_is_set_smaller(self):
        document = Document(
            "Wide",
            (),
            (Section("One", (Table("Narrow", ("A", "B"), ()), Table("Wide", ("A",) * 8, ()))),),
        )
        page = view.page(document)
        assert '<h3>Narrow</h3>\n<div class="scroll"><table>' in page
        assert '<h3>Wide</h3>\n<div class="scroll"><table class="wide">' in page

    def test_a_section_with_no_tables_says_so(self):
        page = view.page(Document("Empty", (), (Section("Nothing here", ()),)))
        assert '<h2>Nothing here</h2>\n<p class="empty">Nothing is stated.</p>' in page
        assert "<dl" not in page

    def test_the_page_for_the_document_this_library_builds_holds_every_point(self, simulation):
        _, document = _built(simulation)
        page = view.page(document)
        for kind in Kind:
            for point in simulation.outstation.served(kind)[:3]:
                assert f"<td>{point.index}</td><td>{point.name}</td>" in page
        served = sum(len(simulation.outstation.served(kind)) for kind in Kind)
        assert page.count("<td>Synthetic ") == served


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """Give the command the synthetic tables to build its outstation from."""
    path = tmp_path / load.TABLES_NAME
    path.write_text(json.dumps(for_reference_der()), encoding="utf-8")
    monkeypatch.setenv(load.TABLES_VARIABLE, str(path))


@pytest.fixture
def no_tables(tmp_path, monkeypatch):
    """Leave the command with no tables to find."""
    monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))


@pytest.mark.usefixtures("tables")
class TestTheCommandWritesThePage:
    def test_html_writes_the_page_for_the_document_it_builds(self, tmp_path, capsys):
        page = tmp_path / "made" / "profile.html"

        assert cli.main(["profile", "--vendor", "Example Co", "--html", str(page)]) == 0

        captured = capsys.readouterr()
        # The document still goes where it went: the page is written as well.
        assert captured.out.startswith("<?xml")
        assert f"wrote {page}" in captured.err
        written = page.read_text(encoding="utf-8")
        assert written == view.page(view.read(captured.out))
        assert "<dt>Vendor name</dt><dd>Example Co</dd>" in written
        assert "<td>0</td><td>Synthetic BI0</td>" in written
        assert html.escape(view.NOTICE) in written

    def test_the_page_is_written_as_utf_8_with_unix_line_endings(self, tmp_path):
        page = tmp_path / "profile.html"
        assert cli.main(["profile", "--vendor", "Caf\u00e9 Works", "--html", str(page)]) == 0
        octets = page.read_bytes()
        assert b"\r" not in octets and octets.endswith(b"</html>\n")
        assert "<dd>Caf\u00e9 Works</dd>".encode() in octets

    def test_out_and_html_write_the_document_and_its_page(self, tmp_path, capsys):
        document, page = tmp_path / "profile.xml", tmp_path / "profile.html"
        assert cli.main(["profile", "--out", str(document), "--html", str(page)]) == 0
        assert capsys.readouterr().out == ""
        assert page.read_text(encoding="utf-8") == view.page(
            view.read(document.read_text(encoding="utf-8"))
        )


@pytest.mark.usefixtures("no_tables")
class TestTheCommandLaysOutAnotherDocument:
    def test_from_lays_out_a_file_with_no_tables_and_no_configuration(self, tmp_path, capsys):
        vendor, page = tmp_path / "vendor.xml", tmp_path / "out" / "vendor.html"
        vendor.write_text(SMALL, encoding="utf-8", newline="\n")
        missing = str(tmp_path / "no-such-configuration.json")

        status = cli.main(
            ["profile", "--from", str(vendor), "--html", str(page), "--config", missing]
        )

        assert status == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.strip() == f"wrote {page}"
        octets = page.read_bytes()
        assert b"\r" not in octets
        assert octets.decode("utf-8") == view.page(SMALL_MODEL)

    def test_a_file_is_decoded_as_it_declares(self, tmp_path):
        vendor, page = tmp_path / "vendor.xml", tmp_path / "vendor.html"
        vendor.write_bytes(
            (
                '<?xml version="1.0" encoding="ISO-8859-1"?>'
                "<DNP3DeviceProfileDocument><documentHeader>"
                "<documentName>Caf\u00e9 feeder</documentName>"
                "</documentHeader></DNP3DeviceProfileDocument>"
            ).encode("iso-8859-1")
        )
        assert cli.main(["profile", "--from", str(vendor), "--html", str(page)]) == 0
        assert "<h1>Caf\u00e9 feeder</h1>" in page.read_text(encoding="utf-8")

    @pytest.mark.parametrize(
        ("text", "says"),
        [
            ("<html><body/></html>", "the document is not a Device Profile: its root element"),
            ("notes", "the document is not XML: "),
        ],
    )
    def test_a_file_that_is_not_a_device_profile_is_reported_and_no_page_is_written(
        self, tmp_path, capsys, text, says
    ):
        vendor, page = tmp_path / "vendor.xml", tmp_path / "vendor.html"
        vendor.write_text(text, encoding="utf-8")
        assert cli.main(["profile", "--from", str(vendor), "--html", str(page)]) == 1
        assert capsys.readouterr().err.startswith(says)
        assert not page.exists()

    def test_a_file_over_the_size_limit_is_reported(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(view, "MAX_SIZE", 2 * 1024 * 1024)
        vendor, page = tmp_path / "vendor.xml", tmp_path / "vendor.html"
        vendor.write_text(SMALL + " " * (2 * 1024 * 1024), encoding="utf-8")
        assert cli.main(["profile", "--from", str(vendor), "--html", str(page)]) == 1
        assert capsys.readouterr().err.strip() == (
            "the Device Profile document is larger than 2 MiB, the most that is read"
        )
        assert not page.exists()

    def test_a_file_that_is_not_there_is_reported(self, tmp_path, capsys):
        absent, page = tmp_path / "absent.xml", tmp_path / "vendor.html"
        assert cli.main(["profile", "--from", str(absent), "--html", str(page)]) == 2
        assert capsys.readouterr().err.startswith(f"cannot read {absent}: ")
        assert not page.exists()

    def test_from_needs_somewhere_to_write_the_page(self, tmp_path, capsys):
        vendor = tmp_path / "vendor.xml"
        vendor.write_text(SMALL, encoding="utf-8")
        assert cli.main(["profile", "--from", str(vendor)]) == 2
        captured = capsys.readouterr()
        assert captured.err.strip() == "--from lays out a document: give --html FILE for the page"
        assert captured.out == ""

    @pytest.mark.parametrize("flag", ["--out", "--validate"])
    def test_from_refuses_the_flags_that_are_for_a_document_it_builds(self, tmp_path, capsys, flag):
        vendor, page = tmp_path / "vendor.xml", tmp_path / "vendor.html"
        vendor.write_text(SMALL, encoding="utf-8")
        other = tmp_path / "other"
        status = cli.main(["profile", "--from", str(vendor), "--html", str(page), flag, str(other)])
        assert status == 2
        assert capsys.readouterr().err.strip() == (
            f"{flag} applies to the document this command builds, and --from builds none"
        )
        assert not page.exists() and not other.exists()

    def test_without_from_the_command_still_needs_its_tables(self, tmp_path, capsys):
        page = tmp_path / "profile.html"
        assert cli.main(["profile", "--html", str(page)]) == 1
        assert not page.exists()
        assert capsys.readouterr().out == ""
