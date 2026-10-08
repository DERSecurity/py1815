# Two images from one file: an IEEE 1815.2 DER outstation, and a DNP3 master
# with its API and web console.
#
#   docker build -t py1815-der .
#   docker run --rm -v py1815-tables:/data py1815-der tables fetch
#   docker run --rm -p 20000:20000 -v py1815-tables:/data py1815-der
#
#   docker build --target master -t py1815-master .
#   docker run --rm -p 127.0.0.1:8815:8815 py1815-master
#
# `compose.yaml` runs the two together: `docker compose up`.
#
# The outstation is the last stage, so a build that names no target makes it,
# as it did when this file made nothing else.
#
# Neither image holds anything of IEEE's. The profile's point tables may not
# be redistributed, so they are not built in: `tables fetch` downloads them
# from IEEE into a volume on the machine that runs it, and both images read
# them from that volume. `.dockerignore` keeps a copy sitting in a checkout
# out of the build context for the same reason.

FROM python:3.12-slim AS base

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


# The master: `py1815-master`, serving its API and the console.
FROM base AS master

EXPOSE 8815

# The console's own page needs no token, so this asks for nothing that would
# have to be told a secret, and says only that the server is answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8815/', timeout=3)"]

ENTRYPOINT ["py1815-master"]
# Every interface inside the container; publishing the port is what decides
# who outside it can reach the console. Listening that widely needs a token,
# so one is made for the run and printed with the address, unless
# PY1815_MASTER_TOKEN gives one that stays the same from run to run.
CMD ["console", "--bind", "0.0.0.0:8815", "--new-token"]


# The outstation: `py1815-der`, serving a simulated DER. The default target.
FROM base AS der

EXPOSE 20000

ENTRYPOINT ["py1815-der"]
# Every interface inside the container; publishing the port is what decides
# who outside it can reach the outstation.
CMD ["run", "--bind", "0.0.0.0:20000"]
