# Installing vyql

**Ask before running any of this.** Downloading and executing a binary on
someone's machine without asking is exactly what a security tool should not do.

Check first:

```sh
vyql version
```

## Release archive (preferred)

No Go toolchain needed. About 14 MB downloaded, 200 MB extracted — nearly all of
it the security knowledge base, which is why the binary works with no further
setup.

Detect the platform, then substitute below:

```sh
uname -s   # Darwin -> darwin, Linux -> linux
uname -m   # arm64/aarch64 -> arm64, x86_64/amd64 -> amd64
```

```sh
V=v0.2.0; P=darwin_arm64        # linux_amd64 | linux_arm64 | darwin_amd64 | darwin_arm64
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz.sha256
shasum -a 256 -c vyql_${V}_${P}.tar.gz.sha256      # or sha256sum -c on Linux
tar -xzf vyql_${V}_${P}.tar.gz
```

**Do not skip the checksum step.** It is the only thing between a substituted
download and running it.

The binary is at `vyql_${V}_${P}/bin/vyql`. It finds its data relative to its own
location, so it can be run from anywhere or put on `PATH`.

Windows is not published. Linux and macOS only, amd64 and arm64.

## go install

For Go developers. Needs Go 1.26+ and a C toolchain, because the parsers are C
compiled by cgo.

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
```

State the real cost before suggesting it: this pulls roughly 950 MB into the
module cache, and the binary resolves its data from there — so `go clean
-modcache` leaves a working binary that cannot find its knowledge base.

## Version

The skill needs **v0.2.0 or newer**. Earlier builds do not have `-fail-on`,
`-coverage` or `-baseline`, and will reject them as unknown flags.

```sh
vyql version
```
