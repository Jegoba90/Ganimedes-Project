# Package the release binaries rather than compile a second copy with a
# different toolchain. Docker remains optional for the standalone gateway
# (Constitution Art. 5.1); the image provides no MCP server or server runtime.
FROM scratch

ARG TARGETARCH
ARG VERSION=0.0.0-dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/Jegoba90/Ganimedes-Project" \
      org.opencontainers.image.description="Local governance and verifiable audit for MCP tool calls" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --chmod=0555 dist/container/linux/${TARGETARCH}/ganimedes /ganimedes
COPY LICENSE /LICENSE

# A read-only log mount is sufficient for verify. Running a server in a derived
# image needs an explicitly writable mount for its log and signing key; /data
# is intentionally not made world-writable to accommodate an arbitrary UID.
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/ganimedes"]
CMD ["help"]
