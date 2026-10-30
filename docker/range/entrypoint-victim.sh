#!/bin/sh
mkdir -p /run/nginx /run /var/lib/nginx/tmp
nginx
exec /usr/sbin/sshd -D -e
