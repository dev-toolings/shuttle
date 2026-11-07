set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/20-docker ]; then
if ! command -v docker >/dev/null 2>&1; then
  . /etc/os-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  arch=$(dpkg --print-architecture)
  . /etc/os-release
  echo "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID ${VERSION_CODENAME} stable" >/etc/apt/sources.list.d/docker.list
  apt-get update -y
  # stack deploy ignores security_opt. Configure the daemon before its first
  # package start, so Swarm tasks inherit no-new-privileges without a second rollout.
  # Existing configuration belongs to the operator; doctor reports any gap.
  if [ ! -e /etc/docker/daemon.json ]; then
    install -m 0755 -d /etc/docker
    printf '%s\n' '{"no-new-privileges":true}' >/etc/docker/daemon.json
  fi
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
mtu_if=$(ip -o -4 route show default | awk '{print $5; exit}')
host_mtu=0
if [ -n "$mtu_if" ] && [ -r "/sys/class/net/$mtu_if/mtu" ]; then
  host_mtu=$(cat "/sys/class/net/$mtu_if/mtu")
fi
case "$host_mtu" in ''|*[!0-9]*) host_mtu=0 ;; esac
if [ "$host_mtu" -ge 1280 ] && [ "$host_mtu" -lt 1500 ] && ! docker network inspect docker_gwbridge >/dev/null 2>&1; then
  docker network create --driver bridge \
    --opt com.docker.network.bridge.name=docker_gwbridge \
    --opt com.docker.network.bridge.enable_icc=false \
    --opt com.docker.network.bridge.enable_ip_masquerade=true \
    --opt com.docker.network.driver.mtu="$host_mtu" \
    docker_gwbridge >/dev/null
fi
docker info --format '{{.Swarm.LocalNodeState}}' | grep -qx active || docker swarm init
if docker network inspect caddy_network >/dev/null 2>&1; then
  edge_driver=$(docker network inspect caddy_network --format '{{.Driver}}')
  if [ "$edge_driver" != overlay ]; then
    echo "caddy_network already exists as a '$edge_driver' network; Swarm services cannot attach to it, so the shared edge and every application would fail to converge." >&2
    echo "Docker cannot change a network's driver or rename it. Move whatever uses it to another network, remove caddy_network, then run setup again. Attached containers:" >&2
    docker network inspect caddy_network --format '{{range .Containers}}{{.Name}} {{end}}' >&2
    exit 1
  fi
else
  docker network create --driver overlay --attachable caddy_network
fi
docker volume inspect shuttle-registry >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system shuttle-registry >/dev/null
docker volume inspect shuttle-registry >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system shuttle-registry >/dev/null
if docker container inspect shuttle-registry >/dev/null 2>&1; then
  registry_user=$(docker container inspect shuttle-registry --format '{{.Config.User}}')
  existing_image=$(docker container inspect shuttle-registry --format '{{.Config.Image}}')
  registry_mount=$(docker container inspect shuttle-registry --format '{{range .Mounts}}{{if eq .Destination "/var/lib/registry"}}{{.Type}}:{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}')
  if [ "$registry_mount" != volume:shuttle-registry ]; then
    echo "refusing to replace loopback registry: /var/lib/registry is mounted from ${registry_mount:-no mount}, expected volume:shuttle-registry" >&2
    exit 1
  fi
  if [ "$existing_image" != 'registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    existing_tag=${existing_image#registry:}
    existing_tag=${existing_tag%%@*}
    desired_image='registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    desired_tag=${desired_image#registry:}
    desired_tag=${desired_tag%%@*}
    existing_major=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9].*//')
    desired_major=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9].*//')
    if [ "$existing_major" != "$desired_major" ]; then
      echo "registry major change $existing_major -> $desired_major requires an explicit migration" >&2
      exit 1
    fi
    # With a major-only tag such as registry:3, the order of two digests cannot be established. The resolved digest is the newest image for that major at resolution time over TLS from the fixed Hub hosts; an older image served under that tag is a supply-chain compromise that version comparison would not prevent. Keep the exact identity recorded for rollback.
    existing_version=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9.].*//')
    desired_version=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9.].*//')
    if [ "$desired_version" != "$desired_major" ] && [ "$(printf '%s\n%s\n' "$existing_version" "$desired_version" | sort -V | head -n 1)" = "$desired_version" ] && [ "$existing_version" != "$desired_version" ]; then
      echo "planned registry version $desired_version is older than running version $existing_version" >&2
      exit 1
    fi
    if [ "$existing_image" != "$desired_image" ]; then
      docker pull --quiet "$desired_image"
    fi
  fi
  if [ "$registry_user" != 10001:10001 ] || [ "$existing_image" != 'registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    docker stop shuttle-registry >/dev/null
    docker rm shuttle-registry >/dev/null
  fi
fi
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges=true --entrypoint /bin/sh -v shuttle-registry:/var/lib/registry registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -ec 'chown -R 10001:10001 /var/lib/registry'

docker container inspect shuttle-registry >/dev/null 2>&1 || docker run -d --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges=true --restart=always --name shuttle-registry --label dev.shuttle.owner=system --log-opt max-size=10m --log-opt max-file=3 --health-cmd '/bin/registry --version >/dev/null' --health-interval 5s --health-timeout 2s --health-retries 10 -e REGISTRY_STORAGE_DELETE_ENABLED=true -p 127.0.0.1:5000:5000 -v shuttle-registry:/var/lib/registry registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

attempt=0
ready=0
while [ "$attempt" -lt 24 ]; do
  if [ "$(docker container inspect shuttle-registry --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)" = healthy ] && curl -fsS --max-time 2 http://127.0.0.1:5000/v2/ >/dev/null; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$ready" != 1 ]; then
  docker container logs --tail 50 shuttle-registry >&2
  exit 1
fi

touch /etc/shuttle/setup.d/20-docker
fi
set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/21-registry-nonroot ]; then
docker volume inspect shuttle-registry >/dev/null 2>&1 || docker volume create --label dev.shuttle.owner=system shuttle-registry >/dev/null
if docker container inspect shuttle-registry >/dev/null 2>&1; then
  registry_user=$(docker container inspect shuttle-registry --format '{{.Config.User}}')
  existing_image=$(docker container inspect shuttle-registry --format '{{.Config.Image}}')
  registry_mount=$(docker container inspect shuttle-registry --format '{{range .Mounts}}{{if eq .Destination "/var/lib/registry"}}{{.Type}}:{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}')
  if [ "$registry_mount" != volume:shuttle-registry ]; then
    echo "refusing to replace loopback registry: /var/lib/registry is mounted from ${registry_mount:-no mount}, expected volume:shuttle-registry" >&2
    exit 1
  fi
  if [ "$existing_image" != 'registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    existing_tag=${existing_image#registry:}
    existing_tag=${existing_tag%%@*}
    desired_image='registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    desired_tag=${desired_image#registry:}
    desired_tag=${desired_tag%%@*}
    existing_major=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9].*//')
    desired_major=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9].*//')
    if [ "$existing_major" != "$desired_major" ]; then
      echo "registry major change $existing_major -> $desired_major requires an explicit migration" >&2
      exit 1
    fi
    # With a major-only tag such as registry:3, the order of two digests cannot be established. The resolved digest is the newest image for that major at resolution time over TLS from the fixed Hub hosts; an older image served under that tag is a supply-chain compromise that version comparison would not prevent. Keep the exact identity recorded for rollback.
    existing_version=$(printf '%s\n' "$existing_tag" | sed 's/[^0-9.].*//')
    desired_version=$(printf '%s\n' "$desired_tag" | sed 's/[^0-9.].*//')
    if [ "$desired_version" != "$desired_major" ] && [ "$(printf '%s\n%s\n' "$existing_version" "$desired_version" | sort -V | head -n 1)" = "$desired_version" ] && [ "$existing_version" != "$desired_version" ]; then
      echo "planned registry version $desired_version is older than running version $existing_version" >&2
      exit 1
    fi
    if [ "$existing_image" != "$desired_image" ]; then
      docker pull --quiet "$desired_image"
    fi
  fi
  if [ "$registry_user" != 10001:10001 ] || [ "$existing_image" != 'registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]; then
    test "$(docker container inspect shuttle-registry --format '{{index .Config.Labels "dev.shuttle.owner"}}')" = system
    docker stop shuttle-registry >/dev/null
    docker rm shuttle-registry >/dev/null
  fi
fi
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --security-opt no-new-privileges=true --entrypoint /bin/sh -v shuttle-registry:/var/lib/registry registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -ec 'chown -R 10001:10001 /var/lib/registry'
docker container inspect shuttle-registry >/dev/null 2>&1 || docker run -d --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges=true --restart=always --name shuttle-registry --label dev.shuttle.owner=system --log-opt max-size=10m --log-opt max-file=3 --health-cmd '/bin/registry --version >/dev/null' --health-interval 5s --health-timeout 2s --health-retries 10 -e REGISTRY_STORAGE_DELETE_ENABLED=true -p 127.0.0.1:5000:5000 -v shuttle-registry:/var/lib/registry registry:3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

touch /etc/shuttle/setup.d/21-registry-nonroot
fi
