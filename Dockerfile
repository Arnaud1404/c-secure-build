# Toolchain only; the repo is mounted at /src.
# ubuntu:24.04
FROM docker.io/library/ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG SNAPSHOT=20260915T000000Z
ENV DEBIAN_FRONTEND=noninteractive

# The snapshot is HTTPS-only, so ca-certificates comes from the live archive.
# Without --error-on=any, a failed fetch is only a warning.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get update --error-on=any --snapshot "$SNAPSHOT" \
 && apt-get install -y --no-install-recommends \
        clang=1:18.0-59~exp2 \
        gcc=4:13.2.0-7ubuntu1 \
        libc6-dev \
        libclang-rt-18-dev \
        make=4.3-4.1build2 \
        python3-venv=3.12.3-0ubuntu2.1 \
        valgrind=1:3.22.0-0ubuntu3 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# Runs as the caller's uid, which has no home; semgrep needs a writable $HOME.
ENV PATH=/opt/scanners/bin:$PATH \
    HOME=/tmp \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SCAN_TOOLCHAIN=image

WORKDIR /src
CMD ["./scripts/scan.sh"]
