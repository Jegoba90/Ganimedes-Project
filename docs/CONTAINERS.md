# Optional container distribution

Ganimedes remains a standalone static binary (Constitution Art. 5.1). The
container is an additional distribution format for Linux `amd64` and `arm64`,
published to `ghcr.io/jegoba90/ganimedes-project` by the release workflow. It
packages the Linux binaries already built for that release, rather than
compiling a second copy inside another toolchain image.

## Available versions

Use a tag listed in the repository's
[Packages](https://github.com/Jegoba90/Ganimedes-Project/pkgs/container/ganimedes-project).
In the commands below, replace `<version>` with that tag, including its `v`
prefix. Older releases do not gain container images retroactively. An empty
package list means the first container release has not been published yet.

```sh
docker run --rm ghcr.io/jegoba90/ganimedes-project:<version> version
```

The image starts `/ganimedes` directly and defaults to `help`. It uses `scratch`,
with no shell, package manager, MCP server or language runtime. Its user and
group are `65532:65532`; its working directory is `/data`.

## Verify an existing log

Place the audit log and its public key in one directory. From that directory,
on Linux or macOS:

```sh
docker run --rm --mount "type=bind,src=$(pwd),dst=/data,readonly" \
  ghcr.io/jegoba90/ganimedes-project:<version> \
  verify --pubkey /data/ganimedes-signing.pub /data/ganimedes-audit.jsonl
```

In PowerShell, use `${PWD}` instead of `$(pwd)` and put the command on one line
or use PowerShell's line continuation. The mounted files must be readable by
the container user. On Linux, `--user "$(id -u):$(id -g)"` can match their owner
without making a sensitive log world-readable. A root-owned `0600` log requires
an appropriate user or ACL; mounting it alone grants no read permission.
Verification needs the public key, never the private signing key. Mount a
directory containing only the files needed for this operation.

## Use Ganimedes with a containerized MCP server

Copy the binary into the image that already contains your server and its
runtime. In that image's Dockerfile, substitute an available version:

```dockerfile
COPY --from=ghcr.io/jegoba90/ganimedes-project:<version> /ganimedes /usr/local/bin/ganimedes
```

For a Node-based server, the resulting image might start with
`ganimedes run -- node /app/server.js`; the server installation is the
responsibility of that image. Keep stdin attached with `docker run -i` and omit
`-t`, because a terminal can change the protocol bytes. Mount a writable data
directory for logs and signing keys, with permissions for the chosen container
user. `/data` in the unmodified image is owned by root and is not writable by
UID `65532`.

`run` and `scan` launch a subprocess inside their own container. They cannot
launch an MCP server installed only on the host or in an adjacent container.
The default image therefore cannot run the README's `npx` examples directly.

Human approval listens on numeric loopback inside the container. `docker -p`
does not expose that listener. This guide does not provide a portable setup for
human approval from a host browser; use the standalone binary when you need
that workflow. A container does not extend the gateway's policy boundary to
processes or calls outside the MCP connection it wraps.

## Verify image provenance

The publishing workflow records the image digest and attests it using GitHub's
Sigstore-backed build provenance. Substitute that digest, without a second
`sha256:` prefix:

```sh
gh attestation verify oci://ghcr.io/jegoba90/ganimedes-project@sha256:<digest> --repo Jegoba90/Ganimedes-Project
docker run --rm ghcr.io/jegoba90/ganimedes-project@sha256:<digest> version
```

The attestation proves where the image came from, not that its code is safe.
Tags can be reassigned; use the verified digest when an exact image matters.

## Build and publish

`Dockerfile` consumes prebuilt Linux binaries at
`dist/container/linux/<arch>/ganimedes`. For a local `amd64` build in a POSIX
shell, from the repository root:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/container/linux/amd64/ganimedes ./cmd/ganimedes
docker build --platform linux/amd64 -t ganimedes:local .
docker run --rm ganimedes:local version
```

In PowerShell, set `$env:CGO_ENABLED = '0'`, `$env:GOOS = 'linux'` and
`$env:GOARCH = 'amd64'` before `go build`, then remove those variables afterward.
An unstamped local binary reports its development version. Building `arm64`
also requires the corresponding binary with `GOARCH=arm64`.

Run `.github/workflows/release.yml` with `workflow_dispatch` to rehearse the full
quality gate, binary builds and container packaging without pushing an image
or creating a release. Tag-triggered runs publish the versioned GHCR image and
its attestation as well as the existing release assets. Publishing a release
still requires the maintainer's confirmation before pushing its tag.

The first GHCR package is private by default, even for a public repository.
After the first publication, the maintainer must open the package's settings
and change its visibility to public before anonymous pulls work. The workflow
uses `GITHUB_TOKEN` and the OCI source label to associate the package with this
repository so it appears in the Packages sidebar. See GitHub's
[Container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
