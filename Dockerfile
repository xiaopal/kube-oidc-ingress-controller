FROM quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.15.0

RUN mkdir /build && cd /build && \
 curl -sSL https://github.com/bungle/lua-resty-session/archive/v2.22.tar.gz | tar -zx && \
 curl -sSL https://github.com/pintsized/lua-resty-http/archive/v0.12.tar.gz | tar -zx  && \
 curl -sSL https://github.com/zmartzone/lua-resty-openidc/archive/v1.5.4.tar.gz | tar -zx && \
 curl -sSL https://github.com/SkyLothar/lua-resty-jwt/releases/download/v0.1.11/lua-resty-jwt-0.1.11.tar.gz | tar -zx && \
 curl -sSL https://github.com/xiaopal/kube-oidc-proxy/archive/v2.1.tar.gz | tar -zx && \
 cp -r */lib/resty/* /usr/local/lib/lua/resty/ && \
 cp kube-oidc-proxy-2.1/openidc_v1.5.4-patch.lua /usr/local/lib/lua/resty/openidc.lua && \
 cp kube-oidc-proxy-2.1/setup.sh / && chmod 0755 /setup.sh && \
 curl -sSL 'https://npc.nos-eastchina1.126.net/dl/jq_1.5_linux_amd64.tar.gz' | tar -zx -C /usr/bin && \
 curl -sSL 'https://npc.nos-eastchina1.126.net/dl/jwks2pem.tar.gz' | tar -zx -C /usr/bin && \
 rm -rf /build && mv /nginx-ingress-controller /nginx-ingress-controller.original

ADD nginx_0.15.0.tmpl /etc/nginx/template/nginx.tmpl
ADD nginx-ingress-controller.sh /nginx-ingress-controller
RUN chmod 0755 /nginx-ingress-controller
