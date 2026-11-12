# Object catalog

Every object group and variation in IEEE 1815-2012 Annex A, by number, name and
size, and a report of which of them this library serves, accepts and reads.

Run the report with:

```bash
python -m py1815.object_coverage            # one line for each variation
python -m py1815.object_coverage --json     # the same rows as JSON
python -m py1815.object_coverage --subset-tables "Request-Response Subset Tables.xlsx"
```

Each variation is marked in three columns. *Served*: the outstation can put the
object in a response. *Requested*: the outstation accepts the object in a request,
as the header of a read, the body of a write or a control, or a class object.
*Parsed*: the master reads the object out of a response. The marks are read from
the tables the library uses, not counted by hand, so the report changes when the
code does. The marks cover every subset level: an object that only a Level 3 or
Level 4 outstation serves or accepts is marked all the same. A read answered in another
variation, such as a 16-bit counter answered in 32 bits, marks the variation read
as requested and the variation sent as served.

The subset level at which an object is required is not kept in this repository.
Give the command your copy of the DNP Users Group subset tables, with
`--subset-tables` or the `PY1815_SUBSET_TABLES` environment variable, and it adds
a `level` column holding the lowest level whose tables list the object. Without
the tables the column is left out.

## Catalog

::: py1815.catalog

## Coverage report

::: py1815.object_coverage
