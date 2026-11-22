#!/bin/sh
set -eu
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K eth0 gro off lro off tso off gso off 2>/dev/null || true
fi
mkdir -p /run/nginx /run /var/lib/nginx/tmp
nginx
exec /usr/sbin/sshd -D -e
