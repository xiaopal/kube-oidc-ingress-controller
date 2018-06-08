#!/bin/bash

CONFIG_NAME="${OIDC_CONFIG:-oidc-auth}"
NGINX_CONFIG="${NGINX_CONFIG_PATH:-/etc/nginx}" && NGINX_CONFIG="${NGINX_CONFIG%/}"
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
    [ -z "$OIDC_JWKS_PREFETCH" ] || [ ! -z "$OIDC_PUBLIC_KEY" ] || {
        OIDC_DISCOVERY="${OIDC_DISCOVERY:-${OIDC_ISSUER:+${OIDC_ISSUER%/}/.well-known/openid-configuration}}"
        [ ! -z "$OIDC_DISCOVERY" ] || {
            echo 'OIDC_DISCOVERY required' >&2
            return 1
        }
        local OIDC_DISCOVERY_CACHE="$(curl -sSL "$OIDC_DISCOVERY")" && [ ! -z "$OIDC_DISCOVERY_CACHE" ] || return 1
        local OIDC_JWKS_URI="$(jq -r '.jwks_uri//empty'<<<"$OIDC_DISCOVERY_CACHE")"
        # 使用 jwks2pem 工具预先导出为pem格式：openidc_v1.5.4.lua 的 openidc_pem_from_rsa_n_and_e 存在缺陷， 不能将jwks正确导出到pem  
        [ ! -z "$OIDC_JWKS_URI" ] && OIDC_PUBLIC_KEY="$(curl -sSL "$OIDC_JWKS_URI" | jwks2pem)" && \
        echo "loaded: $OIDC_JWKS_URI" >&2
    }
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
    ) >>"$NGINX_CONFIG/$CONFIG_NAME.sessions_"
}

rm -f "$NGINX_CONFIG/$CONFIG_NAME.sessions_"
[ -z "$OIDC_CLIENT_ID" ] || config_session || exit 1
OIDC_CONFIG_PATH="${OIDC_CONFIG_PATH:-/etc/$CONFIG_NAME}" && for CONFIG in ${OIDC_CONFIG_PATH//[ ;,:]/ }; do
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
[ ! -f "$NGINX_CONFIG/$CONFIG_NAME.sessions_" ] || \
(jq -sc 'reduce .[] as $item ( {}; . * $item )' "$NGINX_CONFIG/$CONFIG_NAME.sessions_" >"$NGINX_CONFIG/$CONFIG_NAME.sessions" && rm -f "$NGINX_CONFIG/$CONFIG_NAME.sessions_") || exit 1    

[ -z "$1" ] || { echo "$*" >&2 && exec "$@"; }