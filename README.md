## oidc-ingress-controller: 增强版的 nginx-ingress-controller

在nginx-ingress-controller基础上扩展 openid-connect 登录代理功能，支持自动刷新过期的的 id-token (通过刷新 access-token 实现)

Patch 2018-06-17: 负载均衡传入 X-Forwarded-Proto 未同时传入 X-Forwarded-Port 时使用协议默认端口

# Docker Image
```
    docker pull xiaopal/oidc-ingress-controller:0.15.0
```

# Usage

```
---
kind: Secret
apiVersion: v1
metadata:
  name: kube-cluster-openid.config
type: Opaque
data:
  kubernetes.conf: | # base64 encode
    OIDC_ISSUER=https://xxxx.xxxx.xxx/connect
    OIDC_CLIENT_ID=xxxxxxxxxxxxxxxx
    OIDC_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxx
    OIDC_JWKS_PREFETCH=Y
    # OIDC_SCOPE=xxxxxxxxxxxxx
    # SESSION_REDIS=127.0.0.1:6739
    # SESSION_REDIS_AUTH=xxxxxxxxxxxxxxx
  grafana.json: | # base64 encode
    {
      "issuer":"https://xxxx.xxxx.xxx/connect",
      "client_id": "xxxxxxxxxxxxxxxx",
      "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "scope":"openid email",
      "claim_headers": {
          "X-WEBAUTH-USER": "sub",
          "X-WEBAUTH-EMAIL": "email"
      }
    }

---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-ingress-controller
  ...
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
        - name: nginx-ingress-controller
          image: xiaopal/oidc-ingress-controller:0.15.0
          args:
            - /nginx-ingress-controller
            - --default-backend-service=$(POD_NAMESPACE)/default-http-backend
            - --configmap=$(POD_NAMESPACE)/nginx-configuration
            - --tcp-services-configmap=$(POD_NAMESPACE)/tcp-services
            - --udp-services-configmap=$(POD_NAMESPACE)/udp-services
            - --annotations-prefix=nginx.ingress.kubernetes.io
          ...
          volumeMounts:
            - name: openid-config
              mountPath: /etc/oidc-auth
      volumes:
        - name: openid-config
          secret: { secretName: kube-cluster-openid.config }

```

# grafana 认证代理
```
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: monitoring-grafana
spec:
  ...
  template:
    ...
    spec:
      containers:
      - name: grafana
        ...
        env:
        - name: GF_SECURITY_ADMIN_USER
          value: ...
        - name: GF_AUTH_PROXY_ENABLED
          value: "true"
        - name: GF_AUTH_PROXY_HEADER_NAME
          value: "X-WEBAUTH-USER"
        ...
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: monitoring-grafana
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      set $oidc_access 'grafana';
spec:
  rules:
  - host: monitor.k8s.example.local
    http:
      paths:
      - path: /
        backend:
          serviceName: monitoring-grafana
          servicePort: 80

```

# kubernetes-dashboard 认证代理
```
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      set $oidc_access '{
        "name": "kubernetes",
        "id_token_refresh": true, 
        "enc_id_token" : true,
        "claim_headers": { "Authorization": "bearer_enc_id_token" },
        "no_auth_locations": ["/api"],
        "pass_locations": ["/assets","/static","/favicon.ico"]
        }';
spec:
  rules:
  - host: k8s.example.local
    http:
      paths:
      - path: /
        backend:
          serviceName: kubernetes-dashboard
          servicePort: 80

```

# 配置默认值
```
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-configuration
  namespace: kube-system
data:
  http-snippet: |
    map $http_host $oidc_access_fallback {
      hostnames;
      default "deny";
      *.example.local '{
            "issuer": "https://xxxxxxxxxxxxxx",
            "client_id": "xxxxxxxxxxxxxx", 
            "client_secret" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
          }';
      admin.example.local '{
            "issuer": "https://xxxxxxxxxxxx",
            "client_id": "xxxxxxxxxxxxxxxxxxxx", 
            "client_secret" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
          }';
    }


```

# 更多示例
```
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      set $oidc_access '{
        "issuer": "http://xxxxxxxxxxxxxxxxxx/xxx",
        "client_id": "xxxxxxxxxxxxxxxx", 
        "client_secret" : "xxxxxxxxxxxxxxxxx",
        "claim_headers": { "XXXXXX": "xxx" },
        "redirect_path": "/openid-connect",
        "logout_path": "/logout",
        "logout_redirect": "/"
        }';
spec:
  rules:
  - host: xxx.example.local
    http:
      paths:
      - path: /
        backend:
          serviceName: service1

---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard-api
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      set $oidc_access_action 'no-auth';
spec:
  rules:
  - host: k8s.example.local
    http:
      paths:
      - path: /service2/
        backend:
          serviceName: service2

---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard-pub
  namespace: kube-system
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      set $oidc_access '';
      set $oidc_access_action 'pass';
spec:
  rules:
  - host: k8s.example.local
    http:
      paths:
      - path: /assets/
        backend:
          serviceName: service3
```


# Dev/Test
```
docker build -t oidc-ingress-controller:test . && \
docker run -it --rm -v $HOME:/root --network host \
    -e POD_NAME=default -e POD_NAMESPACE=default \
    -e OIDC_ISSUER='https://xxxxxxxxxxxxxxxxxxxxx' \
    -e OIDC_CLIENT_ID=xxxxxxxxxxxxxx \
    -e OIDC_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    oidc-ingress-controller:test /nginx-ingress-controller \
        --default-backend-service=kube-system/default-http-backend \
        --configmap=kube-system/nginx-configuration \
        --annotations-prefix=nginx.ingress.kubernetes.io \
        --kubeconfig /root/.kube/config
```
