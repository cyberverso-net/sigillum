# The development image: the tools of the workflows at pinned versions, so
# that tests and quality gates give the same results on any host. run.sh
# builds it with the values of versions.env as build arguments, and with
# the named context `oracle` set to tools/dss-oracle.

# No default: an image built without run.sh must name a pinned base image.
ARG UBUNTU_IMAGE
FROM ${UBUNTU_IMAGE}

ARG TARGETARCH
ARG TEMURIN_VERSION
ARG TEMURIN_SHA256_AMD64
ARG TEMURIN_SHA256_ARM64
ARG MAVEN_VERSION
ARG MAVEN_SHA512
ARG YQ_VERSION
ARG YQ_SHA256_AMD64
ARG YQ_SHA256_ARM64
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256_AMD64
ARG RUSTUP_SHA256_ARM64
ARG RUST_STABLE
ARG RUST_MSRV
ARG RUST_NIGHTLY
ARG OPENSSL_MANIFEST_VERSION
ARG OPENSSL_MANIFEST_SHA256
ARG OPENSSL_OTHER_VERSION
ARG OPENSSL_OTHER_SHA256
ARG CARGO_LLVM_COV_VERSION
ARG CARGO_MUTANTS_VERSION
ARG CARGO_FUZZ_VERSION
ARG CARGO_DENY_VERSION
ARG CARGO_VET_VERSION

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# The compiler and download tools come from the Ubuntu archive at build time.
# The tools that decide results are downloaded below at pinned versions.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git jq libssl-dev perl pkg-config unzip \
    && rm -rf /var/lib/apt/lists/* \
    && userdel --remove ubuntu

# A download is used only when its digest is the one recorded in versions.env.
RUN case "$TARGETARCH" in \
        amd64) java_arch=x64; java_sha=$TEMURIN_SHA256_AMD64 ;; \
        arm64) java_arch=aarch64; java_sha=$TEMURIN_SHA256_ARM64 ;; \
        *) echo "Unsupported architecture $TARGETARCH"; exit 1 ;; \
    esac \
    && file="OpenJDK21U-jdk_${java_arch}_linux_hotspot_${TEMURIN_VERSION/+/_}.tar.gz" \
    && curl -sSfL -o /tmp/jdk.tar.gz \
        "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${TEMURIN_VERSION/+/%2B}/$file" \
    && echo "$java_sha  /tmp/jdk.tar.gz" | sha256sum -c - \
    && mkdir /opt/java && tar -xzf /tmp/jdk.tar.gz -C /opt/java --strip-components=1 && rm /tmp/jdk.tar.gz \
    && curl -sSfL -o /tmp/maven.tar.gz \
        "https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz" \
    && echo "$MAVEN_SHA512  /tmp/maven.tar.gz" | sha512sum -c - \
    && mkdir /opt/maven && tar -xzf /tmp/maven.tar.gz -C /opt/maven --strip-components=1 && rm /tmp/maven.tar.gz \
    && case "$TARGETARCH" in amd64) yq_sha=$YQ_SHA256_AMD64 ;; arm64) yq_sha=$YQ_SHA256_ARM64 ;; esac \
    && curl -sSfL -o /usr/local/bin/yq \
        "https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/yq_linux_$TARGETARCH" \
    && echo "$yq_sha  /usr/local/bin/yq" | sha256sum -c - \
    && chmod 755 /usr/local/bin/yq

# Each OpenSSL release is built from its published source, as fixtures-openssl.yml builds it.
# A failure of either build fails the step: the calls are joined with &&.
RUN build() { \
        cd /tmp \
        && curl -sSfL -o openssl.tar.gz \
            "https://github.com/openssl/openssl/releases/download/openssl-$1/openssl-$1.tar.gz" \
        && echo "$2  openssl.tar.gz" | sha256sum -c - \
        && tar -xzf openssl.tar.gz && cd "openssl-$1" \
        && ./Configure --prefix="/opt/openssl-$1" --openssldir="/opt/openssl-$1/ssl" no-shared no-tests \
        && make -j"$(nproc)" build_programs \
        && install -D apps/openssl "/opt/openssl-$1/bin/openssl" \
        && cd /tmp && rm -rf openssl.tar.gz "openssl-$1"; \
    } \
    && build "$OPENSSL_MANIFEST_VERSION" "$OPENSSL_MANIFEST_SHA256" \
    && build "$OPENSSL_OTHER_VERSION" "$OPENSSL_OTHER_SHA256" \
    && test -x "/opt/openssl-$OPENSSL_MANIFEST_VERSION/bin/openssl" \
    && test -x "/opt/openssl-$OPENSSL_OTHER_VERSION/bin/openssl"

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    JAVA_HOME=/opt/java
ENV PATH=/usr/local/cargo/bin:/opt/java/bin:/opt/maven/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN case "$TARGETARCH" in \
        amd64) rust_arch=x86_64; rustup_sha=$RUSTUP_SHA256_AMD64 ;; \
        arm64) rust_arch=aarch64; rustup_sha=$RUSTUP_SHA256_ARM64 ;; \
        *) echo "Unsupported architecture $TARGETARCH"; exit 1 ;; \
    esac \
    && curl -sSfL -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$rust_arch-unknown-linux-gnu/rustup-init" \
    && echo "$rustup_sha  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_STABLE" \
        --component clippy,rustfmt,llvm-tools-preview \
    && rm /tmp/rustup-init \
    && rustup target add --toolchain "$RUST_STABLE" wasm32-unknown-unknown aarch64-apple-ios aarch64-linux-android \
    && rustup toolchain install "$RUST_MSRV" --profile minimal \
    && rustup toolchain install "$RUST_NIGHTLY" --profile minimal \
    # `cargo +nightly`, as the fuzzing instructions write it, selects the pinned nightly.
    && ln -s "$RUST_NIGHTLY-$rust_arch-unknown-linux-gnu" "$RUSTUP_HOME/toolchains/nightly-$rust_arch-unknown-linux-gnu" \
    && cargo install --locked "cargo-llvm-cov@$CARGO_LLVM_COV_VERSION" "cargo-mutants@$CARGO_MUTANTS_VERSION" \
        "cargo-fuzz@$CARGO_FUZZ_VERSION" "cargo-deny@$CARGO_DENY_VERSION" "cargo-vet@$CARGO_VET_VERSION" \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo

# The Maven dependencies of tools/dss-oracle, resolved in the home directory
# that run.sh mounts as a volume of this image. Docker copies them into the
# volume when it creates it. Maven is told where its repository is, because
# Java takes the home directory from the user database, not from HOME.
ENV MAVEN_ARGS=-Dmaven.repo.local=/cache/home/.m2/repository
# A stub project with the same pom, one class and one test runs every plugin
# of the build, so that their own dependencies are resolved too.
COPY --from=oracle pom.xml /tmp/dss-oracle/pom.xml
RUN mkdir -p /cache/home /tmp/dss-oracle/src/main/java /tmp/dss-oracle/src/test/java \
    && echo 'final class Stub {}' > /tmp/dss-oracle/src/main/java/Stub.java \
    && printf '%s\n' 'class StubTest {' '    @org.junit.jupiter.api.Test' '    void runs() {}' '}' \
        > /tmp/dss-oracle/src/test/java/StubTest.java \
    && mvn -B -ntp -q -f /tmp/dss-oracle/pom.xml dependency:go-offline verify \
    && rm -rf /tmp/dss-oracle \
    && chmod -R a+rwX /cache && chmod 1777 /cache /cache/home

ENV HOME=/cache/home \
    CARGO_HOME=/cache/home/.cargo \
    SIGILLUM_TESTPKI_OPENSSL=/opt/openssl-${OPENSSL_MANIFEST_VERSION}/bin/openssl \
    SIGILLUM_TESTPKI_OPENSSL_OTHER=/opt/openssl-${OPENSSL_OTHER_VERSION}/bin/openssl \
    PATH=/opt/openssl-${OPENSSL_MANIFEST_VERSION}/bin:${PATH}

COPY entrypoint.sh /usr/local/bin/dev-image-entrypoint
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/dev-image-entrypoint"]
