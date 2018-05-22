#!/bin/bash

NGINX_CONFIG_PATH="/etc" OIDC_CONFIG="oidc-auth" OIDC_JWKS_PREFETCH="Y" /setup.sh && \
OIDC_SESSIONS="$([ -f /etc/oidc-auth.sessions ] && jq -c 'tojson' /etc/oidc-auth.sessions || echo '"{}"')" \
exec /nginx-ingress-controller.original "$@"