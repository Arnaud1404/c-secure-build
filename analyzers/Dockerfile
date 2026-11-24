# syntax=docker/dockerfile:1.7
# Static analysers for the CASTLE comparison. Kept apart from the gate image
# (../Dockerfile) because Infer and ESBMC add about 2 GB that CI does not need.
# Build from the repository root: docker build -f analyzers/Dockerfile .

# ubuntu:24.04, same digest and snapshot as the gate image.
ARG BASE=docker.io/library/ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

FROM ${BASE} AS fetch
ARG SNAPSHOT=20260915T000000Z
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get update --error-on=any --snapshot "$SNAPSHOT" \
 && apt-get install -y --no-install-recommends \
        unzip=6.0-28ubuntu4.1 \
        xz-utils=5.6.1+really5.4.5-1ubuntu0.4 \
 && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:02be62ba931cb43e2d42bbf7abf4bd9a410cf8464cce5453934e25c90a825850 \
    https://github.com/facebook/infer/releases/download/v1.3.0/infer-linux-x86_64-v1.3.0.tar.xz \
    /tmp/infer.tar.xz
ADD --checksum=sha256:6ca6ea531ce680924145fd3058fc3a22a8485153dea0ccd7e4a213cf59da230a \
    https://github.com/esbmc/esbmc/releases/download/v8.8/esbmc-linux.zip \
    /tmp/esbmc.zip
RUN mkdir /opt/infer \
 && tar -xJf /tmp/infer.tar.xz -C /opt/infer --strip-components=1 \
 && unzip -q /tmp/esbmc.zip -d /tmp/esbmc \
 && mv /tmp/esbmc/release /opt/esbmc

FROM ${BASE}
ARG SNAPSHOT=20260915T000000Z
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get update --error-on=any --snapshot "$SNAPSHOT" \
 && apt-get install -y --no-install-recommends \
        clang-18=1:18.1.3-1ubuntu1 \
        clang-tools-18=1:18.1.3-1ubuntu1 \
        cppcheck=2.13.0-2ubuntu3 \
        frama-c-base=20220511-manganese-5build7 \
        gcc=4:13.2.0-7ubuntu1 \
        libc6-dev \
        make=4.3-4.1build2 \
        python3-venv=3.12.3-0ubuntu2.1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /opt/infer /opt/infer
COPY --from=fetch /opt/esbmc /opt/esbmc

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

ENV PATH=/opt/scanners/bin:/opt/infer/bin:/opt/esbmc/bin:/usr/lib/llvm-18/bin:$PATH \
    HOME=/tmp \
    SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /src
CMD ["./analyzers/versions.sh"]
