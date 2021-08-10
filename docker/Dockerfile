FROM ubuntu:20.04
LABEL maintainer="JK"

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

ENV CFLAGS=-Ofast
ENV BUILD_DEPS   curl make build-essential git libevent-dev libexpat1-dev autoconf file libssl-dev byacc
ENV RUNTIME_DEPS bash util-linux coreutils findutils grep libssl1.1 ldnsutils libevent-2.1 expat ca-certificates runit runit-helper jed logrotate libsqlite3-dev

RUN apt-get update; apt-get -qy dist-upgrade; apt-get -qy clean && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

RUN update-ca-certificates 2> /dev/null || true

WORKDIR /tmp

ENV RUSTFLAGS "-C link-arg=-s"

RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building token server from source" && \
    git clone https://github.com/junkurihara/rust-token-server token-server && \
    cd token-server && \
    cargo build --release --no-default-features && \
    mkdir -p /opt/token-server/sbin && \
    ls /tmp/token-server/target/release && \
    mv /tmp/token-server/target/release/rust-token-server /opt/token-server/sbin/ && \
    strip --strip-all /opt/token-server/sbin/rust-token-server && \
    apt-get -qy purge $BUILD_DEPS && apt-get -qy autoremove && \
    rm -fr ~/.cargo ~/.rustup && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

COPY entrypoint.sh /

RUN chmod 755 /entrypoint.sh

EXPOSE 80/udp 80/tcp

CMD ["/entrypoint.sh"]

ENTRYPOINT ["/entrypoint.sh"]
