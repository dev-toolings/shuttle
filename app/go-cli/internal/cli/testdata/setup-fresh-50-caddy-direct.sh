set -eu
install -d -m 0700 /etc/shuttle/setup.d
if [ ! -f /etc/shuttle/setup.d/50-caddy-direct ]; then
cp /tmp/shuttle-caddy-stack.yml /etc/shuttle/caddy-stack.yml
sh /tmp/shuttle-caddy-volumes.sh
install -d -m 0755 /opt/shuttle/caddy/conf.d
printf '%s\n' '# Shuttle application routes are written by the signed root helper.' >/opt/shuttle/caddy/conf.d/00-empty.caddy
install -o root -g root -m 0444 /tmp/shuttle-Caddyfile /etc/shuttle/Caddyfile
docker stack deploy --detach --prune -c /etc/shuttle/caddy-stack.yml shuttle-edge
attempt=0
ready=0
while [ "$attempt" -lt 24 ]; do
  container=$(docker ps -q --filter label=com.docker.swarm.service.name=shuttle-edge_caddy | head -n 1)
  if [ -n "$container" ] && [ "$(docker service ls --filter name=shuttle-edge_caddy --format '{{.Replicas}}')" = "1/1" ] && docker exec "$container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    ready=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 5
done
if [ "$ready" != 1 ]; then
  docker service ps --no-trunc shuttle-edge_caddy >&2
  exit 1
fi

touch /etc/shuttle/setup.d/50-caddy-direct
fi
