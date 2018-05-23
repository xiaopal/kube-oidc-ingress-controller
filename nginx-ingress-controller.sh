#!/bin/bash

NGINX_CONFIG_PATH="/etc" OIDC_CONFIG="oidc-auth" /setup.sh && \
OIDC_CONFIGURATIONS="$([ -f /etc/oidc-auth.sessions ] && jq -c 'objects//{}' /etc/oidc-auth.sessions || echo '"{}"')" \
exec /nginx-ingress-controller.original "$@"