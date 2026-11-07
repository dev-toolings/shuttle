# Build runners

DeployShuttle builds locally when `build.runner` is absent. This preserves the
existing Buildx arguments, the local builder name, the local cache behavior and
the SSH tunnel used for the production registry.

An SSH runner moves BuildKit to a dedicated guest. The guest may be a VM or an
LXC created for builds. Do not use the PVE node or a host that carries unrelated
services. The BuildKit container uses `network=host` so it can reach the
runner's loopback tunnel.

When a remote builder is created, Shuttle resolves the newest stable official
BuildKit release and prints its tag and digest. Existing builders keep their
pinned image and cache across deployments. Removing the builder definition and
then deploying creates a new builder using the current release; this can also
remove the builder cache. Registry lookup failure stops creation.
Before a stored builder is reused, DeployShuttle parses the complete Buildx
node list and requires exactly one node with the expected SSH endpoint,
`docker-container` driver, `network=host` option and pinned image. Local socket,
context and stale or additional node identities are refused before the builder
is stopped or bootstrapped. Docker and Buildx routing environment overrides are
removed from each child process. The private SSH wrapper accepts Docker's
`docker system dial-stdio` command form, then reconstructs the fixed identity,
host key pin and endpoint before starting OpenSSH. Image scanning remains an
optional diagnostic and is never a build prerequisite.

## Configuration

```yaml
build:
  runner: ssh
  host: 203.0.113.40
  user: build
  port: 22
  host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  identity_file: ~/.ssh/shuttle-builder
  registry_identity_file: /home/build/.ssh/registry-tunnel
```

`host_key` is the ED25519 fingerprint of the build guest. Obtain it through a
trusted exact SSH handshake and verify it out of band before saving it in the
configuration. DeployShuttle refuses SSH configuration rewrites of the declared
user or port, then freezes any resolved runner hostname before Docker starts.

`identity_file` is a private key path on the machine running DeployShuttle. It
is used only for the builder connection. `registry_identity_file` is a private
key path already present on the build guest. DeployShuttle never reads it,
copies it, logs it or forwards the deploy account's agent to the guest.

The runner must be a different host from the configured production VPS. The
production SSH user, host, port and verified host key are taken from the
production server configuration. They cannot be overridden by build settings.

## Registry tunnel credential

Pre-provision a separate public key for the registry tunnel on the production
VPS. The corresponding private key belongs on the build guest at the path in
`registry_identity_file`. The authorized key should permit only this local
forward and no interactive session. For example, a key entry can use the
following restrictions after the public key has been verified:

```text
no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc,permitopen="127.0.0.1:5000" ssh-ed25519 AAAA...
```

The production SSH daemon should also restrict this account or key with a
`Match` block. Keep `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:5000`,
`GatewayPorts no`, `PermitTTY no` and `X11Forwarding no` aligned with the
authorized key restrictions. These permissions are operator-managed. Shuttle
does not create an account, install a key or widen an existing `sshd_config`.

During a deploy the build guest starts its own OpenSSH process with
`ExitOnForwardFailure=yes`, strict known_hosts verification and a loopback bind:

```text
127.0.0.1:5000 -> build guest SSH -> production VPS 127.0.0.1:5000
```

The process has an app-scoped PID and state path. Cleanup checks the process
birth identity, command line marker and socket inode before sending a signal,
so a recycled PID or unrelated listener cannot be treated as this tunnel. The
tunnel is supervised by a foreground runner control session with heartbeats.
The session has a bounded lifetime and closes the owned tunnel and BuildKit
daemon after disconnect, signal or heartbeat expiry. A failed bind or lost
transport fails the deploy and names the runner.

Before stopping any existing builder or opening port 5000, the runner acquires
an exclusive lease. The lease records the run token, application, runner,
production target, boot identity, process birth and expiry. Builder names and
cache identities include the runner, target and application tuple.

## Build and cache behavior

DeployShuttle stops the app-scoped remote BuildKit daemon before connecting to
production, starts or bootstraps it before a build, and stops it on success,
failure and operator signals. The Docker builder definition and its cache volume
survive between runs. Remote builds use `--push` and never use `--load`, so
layers do not pass through the laptop.

The remote cache stays in the persistent BuildKit volume on the runner. The SSH
runner does not export a `mode=max` cache manifest to the production registry.
After the build, the laptop uses its own verified VPS forward only to resolve
the pushed manifest digest. Swarm receives the same loopback pull reference as a
local build: `127.0.0.1:5000/<repository>@sha256:<digest>`.

## Readiness

Run `shuttle doctor` against the production configuration after provisioning.
The registry check passes only when `shuttle-registry` is running and healthy,
uses `restart=always`, and publishes exactly `127.0.0.1:5000`. The builder host
is not presented as production readiness evidence because it is a separate
guest with its own operator-managed lifecycle.
