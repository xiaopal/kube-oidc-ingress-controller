FROM quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.17.1

USER root

RUN mkdir /build && cd /build && \
 curl -sSL https://github.com/bungle/lua-resty-session/archive/v2.22.tar.gz | tar -zx && \
 curl -sSL https://github.com/pintsized/lua-resty-http/archive/v0.12.tar.gz | tar -zx  && \
 curl -sSL https://github.com/zmartzone/lua-resty-openidc/archive/v1.6.1.tar.gz | tar -zx && \
 curl -sSL https://github.com/SkyLothar/lua-resty-jwt/releases/download/v0.1.11/lua-resty-jwt-0.1.11.tar.gz | tar -zx && \
 curl -sSL https://github.com/openresty/lua-resty-redis/archive/v0.26.tar.gz | tar -zx && \
 curl -sSL https://github.com/openresty/lua-resty-upstream-healthcheck/archive/v0.05.tar.gz | tar -zx && \
 cp -r */lib/resty/* /usr/local/lib/lua/resty/ && \
 # hmac.lua兼容openssl 1.1
 curl -sSL https://github.com/jkeys089/lua-resty-hmac/raw/master/lib/resty/hmac.lua  >/usr/local/lib/lua/resty/hmac.lua && \
 curl -sSL 'https://npc.nos-eastchina1.126.net/dl/jq_1.5_linux_amd64.tar.gz' | tar -zx -C /usr/bin && \
 rm -rf /build && mv /nginx-ingress-controller /nginx-ingress-controller.original

# evp.lua兼容openssl 1.1
ADD evp_openssl11-patch.lua /usr/local/lib/lua/resty/evp.lua
# openidc.lua 支持 id_token 刷新
ADD openidc_v1.6.1-patch.lua /usr/local/lib/lua/resty/openidc.lua

ADD nginx_0.17.1.tmpl /etc/nginx/template/nginx.tmpl
ADD nginx-ingress-controller.sh /nginx-ingress-controller
ADD oidc-access.lua /
RUN chmod 0755 /nginx-ingress-controller && mkdir -p /tmp/client-body /tmp/proxy-temp && chown -R www-data:www-data /tmp

USER www-data
