#!/bin/bash

SESSION_NAME="${OIDC_SESSION_NAME:-openid}"
SESSION_SECRET="$OIDC_SESSION_SECRET"
SESSION_REDIS="$OIDC_SESSION_REDIS"
SESSION_REDIS_PREFIX="$OIDC_SESSION_REDIS_PREFIX"
SESSION_REDIS_AUTH="$OIDC_SESSION_REDIS_AUTH"

config_session(){
    local SESSION_JSON="$1"
    echo "oidc configuration: $SESSION_NAME" >&2
    local OIDC_JWKS_PREFETCH="$OIDC_JWKS_PREFETCH" OIDC_PUBLIC_KEY="$OIDC_PUBLIC_KEY" OIDC_ISSUER="$OIDC_ISSUER" OIDC_DISCOVERY="$OIDC_DISCOVERY"
    [ ! -z "$SESSION_JSON" ] && [ -z "$OIDC_JWKS_PREFETCH" ] && OIDC_JWKS_PREFETCH="$(jq -r '.jwks_prefetch//empty' "$SESSION_JSON")"
    [ ! -z "$SESSION_JSON" ] && [ -z "$OIDC_PUBLIC_KEY" ] && OIDC_PUBLIC_KEY="$(jq -r '.public_key//empty' "$SESSION_JSON")"
    [ ! -z "$SESSION_JSON" ] && [ -z "$OIDC_ISSUER" ] && OIDC_ISSUER="$(jq -r '.issuer//empty' "$SESSION_JSON")"
    [ ! -z "$SESSION_JSON" ] && [ -z "$OIDC_DISCOVERY" ] && OIDC_DISCOVERY="$(jq -r '.discovery//empty' "$SESSION_JSON")"

    ( export SESSION_NAME SESSION_SECRET \
                SESSION_REDIS SESSION_REDIS_PREFIX SESSION_REDIS_AUTH \
                OIDC_CLIENT_ID OIDC_CLIENT_SECRET \
                OIDC_DISCOVERY OIDC_ISSUER OIDC_PUBLIC_KEY \
                OIDC_SCOPE OIDC_REDIRECT_PATH OIDC_LOGOUT_PATH OIDC_LOGOUT_REDIRECT; jq -nc '{
        name: env.SESSION_NAME,
        scope: env.OIDC_SCOPE,
        redirect_path: env.OIDC_REDIRECT_PATH,
        logout_path: env.OIDC_LOGOUT_PATH,
        logout_redirect: env.OIDC_LOGOUT_REDIRECT,
        session_secret: env.SESSION_SECRET,
        discovery: env.OIDC_DISCOVERY,
        issuer: env.OIDC_ISSUER,
        client_id: env.OIDC_CLIENT_ID,
        client_secret: env.OIDC_CLIENT_SECRET,
        public_key: env.OIDC_PUBLIC_KEY,
        session_redis: env.SESSION_REDIS,
        session_redis_auth: env.SESSION_REDIS_AUTH,
        session_redis_prefix: env.SESSION_REDIS_PREFIX
    } | with_entries(select( .value//"" | length>0 )) 
      | [{key: .name, value:.}] | from_entries' || exit 1
    [ -z "$SESSION_JSON" ] || jq -c 'objects | [{key: env.SESSION_NAME, value:.}] | from_entries' "$SESSION_JSON"
    ) >>"$CONFIG_TMP"
}

CONFIG_TMP='/tmp/sessions.tmp' && rm -f "$CONFIG_TMP"
[ -z "$OIDC_CLIENT_ID" ] || config_session || exit 1
OIDC_CONFIG_PATH="${OIDC_CONFIG_PATH:-/etc/oidc-auth}" && for CONFIG in ${OIDC_CONFIG_PATH//[ ;,:]/ }; do
    [ -d "$CONFIG" ] || continue
    for SESSION_JSON in "${CONFIG%/}"/*.json; do
        [ -f "$SESSION_JSON" ] || continue
        ( SESSION_NAME="${SESSION_JSON%%.*}" && SESSION_NAME="${SESSION_NAME##*/}" && config_session "$SESSION_JSON" ) || exit 1
    done 
    for SESSION_CONF in "${CONFIG%/}"/*.conf; do
        [ -f "$SESSION_CONF" ] || continue
        ( SESSION_NAME="${SESSION_CONF%%.*}" && SESSION_NAME="${SESSION_NAME##*/}" && . "$SESSION_CONF" && config_session ) || exit 1
    done 
done
[ -f "$CONFIG_TMP" ] && {
    export OIDC_CONFIGURATIONS="$(jq -sc 'reduce .[] as $item ( {}; . * $item )' "$CONFIG_TMP")" && [ ! -z "$OIDC_CONFIGURATIONS" ] || exit 1
    rm -f "$CONFIG_TMP"
}
[ -f /etc/oidc-auth.sessions ] && {
    export OIDC_CONFIGURATIONS="$(jq -c 'objects' /etc/oidc-auth.sessions)" && [ ! -z "$OIDC_CONFIGURATIONS" ] || exit 1
}

EXT_OIDC_CONFIGURATIONS="${EXT_OIDC_CONFIGURATIONS:-${OIDC_CONFIGURATIONS:-{\}}}" \
EXT_ANNOTATIONS_PREFIX="${EXT_ANNOTATIONS_PREFIX:-ext.ingress.kubernetes.io}" \
exec /nginx-ingress-controller.original "$@"