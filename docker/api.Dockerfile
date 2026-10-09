# Counselor NIDS — API image, WITH Snort 3 compiled in.
#
# Debian ships no Snort 3 package, so we build it from source (matching the
# project's 3.12.2.0) in a throwaway stage and copy the result into the final
# image. With Snort on PATH, the dashboard's recording tests run the full
# system — the AI *and* Snort as a counselor — not the ML alone.

# ---------- stage 1: build Snort 3 + libdaq from source ----------
FROM python:3.14-slim AS snort-build
ARG SNORT_VERSION=3.12.2.0
ARG DAQ_VERSION=3.0.27
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config autoconf libtool flex bison libfl-dev \
      wget ca-certificates \
      libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev \
      libluajit-5.1-dev zlib1g-dev libssl-dev liblzma-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*
# Snort looks for <dnet.h>; Debian's package installs it as <dumbnet.h>.
RUN ln -sf /usr/include/dumbnet.h /usr/include/dnet.h

WORKDIR /src
RUN wget -q "https://github.com/snort3/libdaq/archive/refs/tags/v${DAQ_VERSION}.tar.gz" -O daq.tgz \
 && tar xf daq.tgz && cd "libdaq-${DAQ_VERSION}" \
 && ./bootstrap && ./configure --prefix=/usr/local \
 && make -j"$(nproc)" && make install && ldconfig

RUN wget -q "https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz" -O snort3.tgz \
 && tar xf snort3.tgz && cd "snort3-${SNORT_VERSION}" \
 && ./configure_cmake.sh --prefix=/usr/local --build-type=Release \
 && cd build && make -j"$(nproc)" && make install

# ---------- stage 2: the application image ----------
FROM python:3.14-slim

# Snort's runtime libraries (the dev packages from stage 1, runtime only).
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 libpcre2-8-0 libdumbnet1 libhwloc15 libluajit-5.1-2 \
      zlib1g libssl3 liblzma5 libuuid1 libnuma1 \
    && rm -rf /var/lib/apt/lists/*

# Snort itself (binary, libs, lua modules, headers) from the build stage.
COPY --from=snort-build /usr/local /usr/local
# nids.lua does `include 'snort_defaults.lua'`, found via `--include-path /etc/snort`.
# A source build keeps the stock config under /usr/local/etc/snort, so point /etc/snort at it.
RUN ldconfig && ln -sfn /usr/local/etc/snort /etc/snort && snort --version

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY snort ./snort
# Editable install: the package keeps living in /app/src, so paths it derives from its own
# location (e.g. snort/nids.lua, models/live/) resolve to /app, exactly as on a dev machine.
RUN pip install --no-cache-dir -e ".[web,live]"
COPY backend ./backend

# Snort's community rules (best-effort; the project's own rules always load).
ARG SNORT_COMMUNITY=1
RUN if [ "$SNORT_COMMUNITY" = "1" ]; then \
      mkdir -p snort/rules/community && \
      (wget -qO- https://www.snort.org/downloads/community/snort3-community-rules.tar.gz \
        | tar xz -C snort/rules/community --strip-components=1 \
        || echo "community rules unavailable at build time — Snort uses snort/rules/nids.rules only"); \
    fi

COPY docker/entrypoint.api.sh /usr/local/bin/entrypoint.api.sh
RUN chmod +x /usr/local/bin/entrypoint.api.sh

ENV NIDS_ROOT=/app
ENTRYPOINT ["nids"]
