# Inconsistencies in the standards

This file lists the places where a standard this library implements disagrees with itself or
with a related document. Each entry says where the disagreement is, what each side says, and
what py1815 does about it. Clause, table and point numbers refer to the editions named in
each heading. The standards' text is not reproduced here.

When you find a new disagreement, add it here with the same parts, and tie the code that
resolves it to a decision in [docs/DESIGN.md](docs/DESIGN.md).

## IEEE Std 1815.2-2025 (DNP3 profile for DER communications)

### Active power limit as a percentage: which point limits charging and which limits generation

The two points are AO87 ("Active Power Limit Maximum") and AO88 ("Active Power Limit
Minimum").

- **AO88 limits generation and AO87 limits charging** according to:
  - equations (7) and (8) in 6.4.2.2, which divide AO87 by the maximum charging power (AI33)
    and AO88 by the maximum generation power (AI32);
  - the predecessor application note, DNP3 AN2018-001 (2.6.1), which names AO87 the charge
    setpoint and AO88 the generation setpoint.
- **AO87 is the generation limit and AO88 the lower one** according to:
  - the point names, "Maximum" and "Minimum";
  - Table 35, steps 8 and 9, which use AO87 to set the maximum generation limit and AO88 to set
    the minimum generation limit;
  - the examples of Figure 24 in 6.4.2.3, which also pair AO87 with the generation limit and
    AO88 with the minimum generation;
  - the IEC 61850 references of the two points, DWMX.WLimPct and DWMN.WLimPct.
- **The sign cannot be sent.** Both point names say a positive value is generation and a
  negative value is consumption, and Table 35 asks for negative values. The point tables
  give both points a range of 0 to 1000.

**py1815:** AO88 limits generation and AO87 limits charging (`AO_POWER_LIMIT_GENERATION` and
`AO_POWER_LIMIT_CHARGING` in `src/py1815/profile/der.py`). DNP3 counts generated power as the
negative direction, so the "minimum" is the generation limit and the "maximum" the charging
limit. Read that way, the equations and the names describe the same assignment.

### Curve dependent units, value 4: percent of watts or percent of apparent power

- **The point tables:** value `<4>` of AO248 (Dependent (Y-Value) Units for Curve) is vars as a
  percentage of maximum watts (WMax), marked "not used".
- **Table 51 (6.5.3):** value `<4>` is vars as a percentage of maximum apparent power (VAMax,
  ChaVAMax), and the table marks it as the setting IEEE Std 1547-2018 uses.

**py1815:** does not interpret AO248. A master or outstation that does needs to choose
between the two.

### Frequency-watt droop deadbands: two sets of points

- **6.4.3.1 and Table 36:** the lower frequency deadband is set in AO482 (reported in AI592)
  and the upper one in AO483 (AI593).
- **The point tables:** AO482 and AO483 are "Droop Minimum Active Power" and "Droop Maximum
  Active Power", in watts. The frequencies at which the frequency-watt function starts are
  AO62 (High Starting Frequency) and AO66 (Low Starting Frequency), which is where the IEEE Std
  1547 mapping in Table 2 places the droop parameters.

**py1815:** does not interpret these points.

### Frequency-watt droop gradients: lower and upper swapped

- **6.4.3.1 and equations (9) and (10):** the lower gradient is AO480 (AI590) and the upper
  gradient is AO481 (AI591).
- **The point tables:** AO480 is "High Frequency-Watt Droop Upper Gradient" and AO481 is "Low
  Frequency-Watt Droop Lower Gradient".

**py1815:** does not interpret these points.

### Frequency-watt droop gradients: the sign of a normal droop

- **The text:** 6.4.3.3 says a negative gradient means the DER reduces active power as
  frequency increases, which is the normal droop shown in Figure 25 and described in 6.4.3.1.
  The gradient points of the sensitivity function, AO64 and AO68, are signed.
- **The point tables:** AO480 and AO481 (W per Hz) have a range of 0 to 2147483647, so a normal
  droop cannot be written to them as a negative value.

**py1815:** does not interpret these points.

### The point table workbook disagrees with itself

The Profile Companion Data Point Tables workbook disagrees with itself in these places:
- the start of the auto-discovery block (analog input 65000 in clause 5.2 and the rows, 60000
  on the Key sheet);
- three equipment block lengths that are one short on the Key sheet;
- two spellings of point references.

[conformance/README.md](conformance/README.md#where-the-workbook-disagrees-with-itself)
describes each one and how the extractor resolves it.

## IEEE Std 1815-2012 (DNP3)

### Object library (Annex A)

These object definitions contradict themselves. `scripts/extract_conformance.py` corrects each
by name, and fails if a later edition fixes the text.

- **Group 32 variation 8** (A.16.8, analog input event, double-precision floating point with
  time): the formal structure types the value FLT32 under a double-precision heading. The
  object is 15 octets: a flag, an 8-octet value and a 6-octet time.
- **Group 33 variation 8** (A.17.8, frozen analog input event): the same error.
- **Group 86 variation 2** (data set descriptor, characteristics): the formal structure types
  the characteristics as BSTR4, four bits, while the pictorial shows one octet. The object is
  one octet.
- **Group 23 variation 8** (A.13.8, frozen counter event, 16-bit with flag and time, delta):
  the header box gives the type as Static. The object is an event.

### Which subset level requires device attributes (group 0)

- **Clause 14.3.2 (Level 1):** a Level 1 outstation accepts reads of specific variations of
  group 0.
- **Clause 14.5.2 (Level 3):** a Level 3 outstation processes reads of all group 0 variations
  and writes of specific ones.
- **Clause 14.6.2 (Level 4):** lists device attributes as one of Level 4's additions.
- **The subset tables in TB2016-003b:** tick group 0 for Level 4 only.

TB2014-001 (IEEE 1815-2012 errata) removes the group 0 bullets from 14.3.2 and 14.5.2, which
leaves Level 4 as the only level that requires device attributes. The printed standard still
carries the bullets.

**py1815:** follows the subset tables and TB2014-001. Device attributes are a Level 4 item.

### Attribute sets with none supported (A.1.3.2.2)

A.1.3.2.2 says that when no attribute sets are supported, the data type code of attribute
variation 211 is 254. Its data type explanation for the same attribute says VSTR. TB2014-001
corrects the note to VSTR with length 0.

**py1815:** sends VSTR with length 0, as TB2014-001 says.

### Level 4 items the subset tables do not carry

Clause 14.6.2 lists self-address reservation (destination 0xFFFC) and the LAN time
synchronization method among Level 4's additions. In the TB2016-003b subset tables, the LAN
method's object (g50v4) has no level ticked, and IED Certification Procedure 3.1 rev 1 (Table
1-1) treats self-addressing as optional.

**py1815:** treats both as optional, as the subset tables do.

## DNP3 TB2016-003b (Updated Subset Parsing Tables)

### Two copies of the workbook differ

The bulletin's zip file and the separately distributed `Request-Response Subset Tables.xlsx`
differ in Table 12-91. In the zip copy, COLD_RESTART (function code 13) is ticked for levels
1 to 4. In the separate copy, the level cells of that row are blank.

**py1815:** uses the copy in the bulletin's zip file.

## DNP3 IED Certification Test Procedures 3.1 rev 1

### Disabling unsolicited responses on a device with them configured off

Section 8.11.2.6, steps 14 and 15, expect a disable request to be refused with IIN2.0 by a device
whose unsolicited responses are configured off. Section 8.11.1 has such a device behave as one
without the feature. IEEE Std 1815-2012 allows the refusal but does not require it: 4.4.13 does
not oblige an outstation without unsolicited responses to implement function codes 20 and 21,
and 4.5.9 answers an unsupported function code with IIN2.0. The procedure therefore requires
more than the standard does.

**py1815:** refuses the request with IIN2.0, so the outstation meets both.
