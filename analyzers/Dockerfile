# syntax=docker/dockerfile:1.7
# Static analysers for the CASTLE comparison, each at its latest stable release
# on 24 November 2026. Kept apart from the gate image (../Dockerfile), which
# stays on Ubuntu 24.04 so the v2 tags keep their results.
# Build from the repository root: docker build -f analyzers/Dockerfile .

# ubuntu:26.10, the newest release, for GCC 16.2. It is supported until
# July 2027, which covers this study; 26.04 LTS only ships a GCC 16 snapshot.
ARG BASE=docker.io/library/ubuntu@sha256:29ac5e68db830ab61b7d77c1ffdb78c73f0631de88a5d77bf4399868f64f38dd
ARG SNAPSHOT=20261124T000000Z

FROM ${BASE} AS apt-base
ARG SNAPSHOT
ENV DEBIAN_FRONTEND=noninteractive
# The snapshot is HTTPS-only, so ca-certificates comes from the live archive.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get update --error-on=any --snapshot "$SNAPSHOT"

FROM apt-base AS fetch
RUN apt-get install -y --no-install-recommends \
        unzip=6.0-31ubuntu1 \
        xz-utils=5.8.3-1ubuntu1
ADD --checksum=sha256:bd4d1c434ff69ef06d19e7934c04708da677e5f2eb51f5bcf052ab91818f0094 \
    https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.6/LLVM-23.1.6-Linux-X64.tar.xz \
    /tmp/llvm.tar.xz
ADD --checksum=sha256:02be62ba931cb43e2d42bbf7abf4bd9a410cf8464cce5453934e25c90a825850 \
    https://github.com/facebook/infer/releases/download/v1.3.0/infer-linux-x86_64-v1.3.0.tar.xz \
    /tmp/infer.tar.xz
ADD --checksum=sha256:6ca6ea531ce680924145fd3058fc3a22a8485153dea0ccd7e4a213cf59da230a \
    https://github.com/esbmc/esbmc/releases/download/v8.8/esbmc-linux.zip \
    /tmp/esbmc.zip
# The full LLVM release is 2 GB; the analyser needs clang, its headers and scan-build.
RUN mkdir /opt/llvm /opt/infer \
 && tar -xJf /tmp/llvm.tar.xz -C /opt/llvm --strip-components=1 --wildcards \
        '*/bin/clang' '*/bin/clang-23' '*/bin/scan-build' '*/lib/clang/*' \
        '*/libexec/ccc-analyzer' '*/libexec/c++-analyzer' '*/share/scan-build/*' \
 && tar -xJf /tmp/infer.tar.xz -C /opt/infer --strip-components=1 \
 && unzip -q /tmp/esbmc.zip -d /tmp/esbmc \
 && mv /tmp/esbmc/release /opt/esbmc

FROM apt-base AS cppcheck
RUN apt-get install -y --no-install-recommends \
        cmake=4.3.4-1ubuntu1 \
        g++=4:15.2.0-5ubuntu1 \
        make=4.4.1-3 \
        python3=3.14.7-3
ADD --checksum=sha256:d74945deb2d50393430e07596b766f8a779512c7f60dac2a30ea64e059ece57b \
    https://github.com/danmar/cppcheck/archive/refs/tags/2.22.0.tar.gz /tmp/cppcheck.tar.gz
# The match compiler is what the release binaries use; without it cppcheck is
# several times slower on the same input.
RUN mkdir /tmp/cppcheck && tar -xzf /tmp/cppcheck.tar.gz -C /tmp/cppcheck --strip-components=1 \
 && cmake -S /tmp/cppcheck -B /tmp/cppcheck/build -DCMAKE_BUILD_TYPE=Release \
        -DUSE_MATCHCOMPILER=On -DCMAKE_INSTALL_PREFIX=/opt/cppcheck -DFILESDIR=/opt/cppcheck/share \
 && cmake --build /tmp/cppcheck/build -j2 \
 && cmake --install /tmp/cppcheck/build

FROM apt-base AS framac
RUN apt-get install -y --no-install-recommends \
        gcc=4:15.2.0-5ubuntu1 \
        git=1:2.55.0-1ubuntu1.1 \
        graphviz=14.1.2-1ubuntu2 \
        libc6-dev=2.44-1ubuntu2.1 \
        libgmp-dev=2:6.3.0+dfsg-5ubuntu2 \
        make=4.4.1-3 \
        ocaml=5.4.1-1ubuntu1 \
        opam=2.5.2-1 \
        patch=2.8-2build1 \
        pkg-config=2.5.1-4 \
        unzip=6.0-31ubuntu1 \
        autoconf=2.73-2 \
        zlib1g-dev=1:1.3.dfsg+really1.3.2-3ubuntu1.1
# opam-repository pinned to a commit, so the dependency solve is the same on rebuild.
ENV OPAMROOT=/opt/opam OPAMYES=1 OPAMJOBS=2
RUN opam init --bare --disable-sandboxing --no-setup default \
        git+https://github.com/ocaml/opam-repository.git#a305f52d0c9f1a98fb88f5fa4c4d2583ddbdbf0b \
 && opam switch create fc ocaml-system \
 && opam install --switch=fc frama-c.33.0 \
 && opam clean --all-switches --download-cache --logs --repo-cache \
 && rm -rf /opt/opam/fc/.opam-switch/sources /opt/opam/fc/doc /opt/opam/fc/man

FROM apt-base
# CASTLE programs link against sqlite3, MySQL, curl and OpenSSL, so their
# headers must be present for the tools that compile the file.
RUN apt-get install -y --no-install-recommends \
        gcc-16=16.2.0-3ubuntu1 \
        graphviz=14.1.2-1ubuntu2 \
        libc6-dev=2.44-1ubuntu2.1 \
        libcurl4-openssl-dev=8.20.0-2ubuntu11.1 \
        libgmp-dev=2:6.3.0+dfsg-5ubuntu2 \
        libmysqlclient-dev=9.7.4-0ubuntu0.26.10.1 \
        libsqlite3-dev=3.53.4-2 \
        libssl-dev=4.0.3-1ubuntu1 \
        make=4.4.1-3 \
        perl=5.42.3-1ubuntu0.1 \
        python3-venv=3.14.7-3 \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/gcc-16 /usr/local/bin/gcc \
 && ln -s /usr/bin/gcc-16 /usr/local/bin/cc

COPY --from=fetch /opt/llvm /opt/llvm
COPY --from=fetch /opt/infer /opt/infer
COPY --from=fetch /opt/esbmc /opt/esbmc
COPY --from=cppcheck /opt/cppcheck /opt/cppcheck
COPY --from=framac /opt/opam/fc /opt/opam/fc

COPY analyzers/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/scanners \
 && /opt/scanners/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# Runs as the caller's uid, which has no home; semgrep needs a writable $HOME.
ENV PATH=/opt/scanners/bin:/opt/llvm/bin:/opt/cppcheck/bin:/opt/infer/bin:/opt/esbmc/bin:/opt/opam/fc/bin:$PATH \
    OCAMLPATH=/opt/opam/fc/lib \
    CAML_LD_LIBRARY_PATH=/opt/opam/fc/lib/stublibs \
    HOME=/tmp \
    SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /src
CMD ["./analyzers/versions.sh"]
