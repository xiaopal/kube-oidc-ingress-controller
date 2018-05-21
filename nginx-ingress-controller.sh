#!/bin/bash
NGINX_CONFIG_PATH="/etc" \
OIDC_CONFIG="oidc-auth" \
OIDC_JWKS_PREFETCH="Y" \
exec /setup-and-exec.sh /nginx-ingress-controller.original "$@"