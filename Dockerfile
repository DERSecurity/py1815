# An IEEE 1815.2 DER outstation: the library, and the `py1815-der` command.
#
#   docker build -t py1815-der .
#   docker run --rm -v py1815-tables:/data py1815-der tables fetch
#   docker run --rm -p 20000:20000 -v py1815-tables:/data py1815-der
#
# The image holds the library and nothing of IEEE's. The profile's point
# tables may not be redistributed, so they are not built in: the second
# command downloads them from IEEE into a volume on the machine that runs it,
# and the third serves from that volume. `.dockerignore` keeps a copy sitting
# in a checkout out of the build context for the same reason.

FROM python:3.12-slim

WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /src

# Unprivileged, and the only place it can write is the volume the tables live in.
RUN useradd --system --no-create-home der \
    && mkdir /data \
    && chown der /data
USER der
WORKDIR /data
VOLUME /data

ENV PY1815_TABLES=/data/ieee-1815-2-2025.json \
    PYTHONUNBUFFERED=1

EXPOSE 20000

ENTRYPOINT ["py1815-der"]
# Every interface inside the container; publishing the port is what decides
# who outside it can reach the outstation.
CMD ["run", "--bind", "0.0.0.0:20000"]
