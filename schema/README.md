# DNP3 Device Profile schema

IEEE Std 1815-2012 section 14.8 defines an XML representation of the DNP3 Device
Profile: the machine-readable description of what an outstation implements and how
it is currently configured. `py1815` targets that representation, so an outstation
built here can emit a Device Profile document that existing DNP3 tooling reads.

This directory holds what we can carry. The normative artifacts themselves are
published by the DNP Users Group and are not redistributable, so they are excluded
from the repository (see [Obtaining the artifacts](#obtaining-the-artifacts)) and
ignored by `.gitignore` so they cannot be committed by accident.

## The artifact set

IEEE Std 1815-2012 section 14.8 describes a package of four files, and notes that
the first three "should be distributed with the DNP3 XML instance file for a
device":

| Artifact | Role |
|---|---|
| `DNP3DeviceProfile<version>.xsd` | The schema every instance document validates against |
| `DNP3DeviceProfile<version>.xslt` | Renders an instance document to browsable HTML |
| `UserData.xslt` | Template stylesheet a vendor customizes to render its `userData` entries |
| `dnp_logo.jpg` | Logo referenced by the rendering stylesheet |

A Device Profile instance is an XML document rooted at `DNP3DeviceProfileDocument`,
carrying a `schemaVersion` attribute and an `<?xml-stylesheet?>` processing
instruction that points at the rendering stylesheet.

## Versions and namespaces

The namespace changed between revisions, and the two are easy to confuse because
one spells the host `dnp3.org` and the other `dnp.org`. A parser that accepts only
one will silently reject documents written against the other.

| Schema | `schemaVersion` | Target namespace |
|---|---|---|
| `DNP3DeviceProfileJan2010.xsd` | `2.07.00` | `http://www.dnp3.org/DNP3/DeviceProfile/Jan2010` |
| `DNP3DeviceProfileApril2016.xsd` | `2.11.00` | `http://www.dnp3.org/DNP3/DeviceProfile/April2016` |
| `DNP3DeviceProfile021200.xsd` | `2.12.00` | `http://www.dnp.org/DNP3/DeviceProfile` |

Instance documents in the wild still carry the 2010 namespace. The device profile
shipped with `opendnp3` and its many downstream forks is one such document, and it
is a useful conformance reference precisely because it is complete and public.

## Obtaining the artifacts

The DNP Users Group distributes the package through its member document library at
<https://www.dnp.org>. Access requires DNP-UG membership; the library redirects
anonymous visitors to a login. The direct download URL that older `opendnp3`
checkouts cite in their `profile/README` is long dead and now returns 404.

Place the files in this directory once obtained. `.gitignore` ignores everything
here except this README, so the package's contents stay untracked whatever a given
release names them, including the examples archive, release notes and
specification documents that ship beside the schema.

## Licensing

`DNP3DeviceProfile<version>.xsd` and `DNP3DeviceProfile<version>.xslt` both carry:

```
COPYRIGHT (c) (1993-2025) DNP Users Group, Inc. All Rights Reserved
```

`UserData.xslt`, `blank-device-profile.xml` and the `dnp_xsl` helper scripts carry
no copyright notice, but an absent notice is not a grant either, so they are
ignored on the same terms.

Neither file carries a redistribution grant, so neither may be committed to this
repository, which is public and Apache-2.0. The note in IEEE Std 1815-2012 that
these files "should be distributed with the DNP3 XML instance file for a device"
describes how a vendor ships a profile for its own product. It is not a copyright
license, and it is not a basis for republishing the artifacts here.

Version 2.12.00 is 2.11.00 with the secure authentication configuration
extended and the namespace changed; nothing was removed. The example profiles
and the blank template in the package are 2.11.00 documents, so they validate
against the April 2016 schema and not against the later one.

## Generating one

`py1815` writes version 2.12.00:

```bash
py1815-der profile --out device-profile.xml --validate schema/DNP3DeviceProfile021200.xsd
```

The generator is `py1815.profile.device_profile`. It needs neither the schema
nor the stylesheet to write the document; `--validate` checks the result
against the copy placed here, and the tests in
`tests/test_profile_device_profile.py` that do the same skip when it is absent.

## Rendering an instance document

With the stylesheet present, any XSLT 1.0 processor produces the human-readable
form. For example, with `xsltproc`:

```bash
xsltproc DNP3DeviceProfile021200.xslt my-device-profile.xml > my-device-profile.html
```

## Related standards

- IEEE Std 1815-2012, section 14.8, defines the XML representation described here.
- IEEE Std 1815.1-2015 maps between IEC 61850 and DNP3 and refers to the same
  DNP-UG device profile material.
- IEEE Std 1815.2-2025 is a different artifact: a DER point profile whose normative
  point list ships as a Companion Data Point Tables spreadsheet, published free on
  the IEEE SA downloads page rather than through DNP-UG.
