# VyQL in a container.
#
#   docker build -t vyql --build-arg VYQL_VERSION=v0.2.0 .
#   docker run --rm -v "$PWD:/work" vyql scan .
#
# Built from the published release rather than from source. The parsers are C
# compiled by cgo, so building here would need a full Go and C toolchain in the
# builder stage to produce a binary that release.yml already builds, tests on a
# native runner, and checksums.

ARG VYQL_VERSION=v0.2.0

FROM debian:stable-slim AS fetch
ARG VYQL_VERSION
# TARGETARCH comes from the builder and is amd64 or arm64, which is exactly what
# the release names its assets. Cross-building this image therefore needs no
# mapping table.
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
RUN set -eu; \
    name="vyql_${VYQL_VERSION}_linux_${TARGETARCH}"; \
    base="https://github.com/vyprai/vyql/releases/download/${VYQL_VERSION}"; \
    curl -fsSLO "${base}/${name}.tar.gz"; \
    curl -fsSLO "${base}/${name}.tar.gz.sha256"; \
    sha256sum -c "${name}.tar.gz.sha256"; \
    tar -xzf "${name}.tar.gz"; \
    mv "${name}" /opt/vyql; \
    # The binary must find its data next to itself, so bin/ and vyql/ move
    # together. Splitting them is how this image would start and detect nothing.
    test -x /opt/vyql/bin/vyql; \
    test -d /opt/vyql/vyql

FROM debian:stable-slim
LABEL org.opencontainers.image.source="https://github.com/vyprai/vyql" \
      org.opencontainers.image.description="Multi-language taint and graph security scanner" \
      org.opencontainers.image.licenses="Apache-2.0"

# The binary is cgo-linked against glibc, so a musl base such as alpine would
# fail at exec with a message about a missing loader.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 vyql

COPY --from=fetch /opt/vyql /opt/vyql
RUN ln -s /opt/vyql/bin/vyql /usr/local/bin/vyql

# Scanning someone's source needs no privileges, and a scanner that writes as
# root into a mounted working tree is a bad neighbour.
USER vyql
WORKDIR /work

ENTRYPOINT ["/opt/vyql/bin/vyql"]
CMD ["scan", "."]
