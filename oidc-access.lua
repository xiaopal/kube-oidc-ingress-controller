local oidc_access = ngx.var.oidc_access
oidc_access = oidc_access ~= "" and oidc_access or ngx.var.oidc_access_fallback
if oidc_access and oidc_access ~= "" then
    if oidc_access == "deny" then
        ngx.status = 403
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    
    local cjson = require("cjson")
    local decode_cfg = oidc_access:match("{.*}") and cjson.decode(oidc_access) or {name=oidc_access}
    local cfg = { name = decode_cfg and decode_cfg["name"] or "openid" }
    local oidc_access_extras = ngx.var.oidc_access_extras
    local extras = oidc_access_extras and oidc_access_extras:match("{.*}") and cjson.decode(oidc_access_extras)
    for k,v in pairs(oidc_configurations[cfg["name"]] or {}) do cfg[k] = v end
    for k,v in pairs(decode_cfg or {}) do cfg[k] = v end
    for k,v in pairs(extras or {}) do cfg[k] = v end
    if cfg["issuer"] and not cfg["discovery"] then
        cfg["discovery"] = cfg["issuer"]:gsub("/$","") .. "/.well-known/openid-configuration"
    end
    if not (cfg["discovery"] and cfg["client_id"] and cfg["client_secret"]) then
        ngx.log(ngx.ERR, cfg["name"] .. ": discovery, client_id and client_secret required.")            
        ngx.status = 500
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    local session_contents = {id_token=true, user=true}
    if cfg["enc_id_token"] then
        session_contents["enc_id_token"] = true
    end
    if cfg["id_token_refresh"] then
        session_contents["access_token"] = true
    end

    local opts = {
        scope = cfg["scope"] or "openid",
        redirect_uri_path = cfg["redirect_path"] or "/" .. cfg["name"] .. "-connect",
        logout_path = cfg["logout_path"] or "/" .. cfg["name"] .. "-logout",
        redirect_after_logout_uri = cfg["logout_redirect"] or "/",
        discovery = cfg["discovery"],
        client_id = cfg["client_id"],
        client_secret = cfg["client_secret"],
        session_contents = session_contents
    }
    if cfg["public_key"] then
        opts["secret"] = cfg["public_key"]
    end
    if cfg["id_token_refresh"] then
        opts["id_token_refresh"] = cfg["id_token_refresh"]
        if cfg["id_token_refresh_interval"] then
            opts["id_token_refresh_interval"] = cfg["id_token_refresh_interval"]
        end
    end
    local redis = cfg["session_redis"]
    local session_name = cfg["session_name"] or (cfg["name"] .. "$session")
    local session_opts = {
        name       = session_name,
        secret     = cfg["session_secret"] or cfg["client_secret"],
        storage    = redis and "redis" or "cookie",

        prefix     = cfg["session_redis_prefix"] or ("sessions:" .. session_name),
        host       = redis and redis:match("([^:]+):%d+") or redis or "127.0.0.1",
        port       = tonumber(redis and redis:match("[^:]+:(%d+)") or 6379),
        auth       = cfg["session_redis_auth"] or nil
    }

    local request_path = ngx.var.request_uri
    request_path = request_path:match("(.-)%?") or request_path

    -- 兼容 mod_auth_openidc: 支持 /redirect_uri?logout=uri 方式登出
    if request_path == opts["redirect_uri_path"] then
        local logout_redirect = ngx.var.arg_logout
        if logout_redirect then
            opts["redirect_uri_path"] = opts["redirect_uri_path"].."$disabled"
            opts["logout_path"] = request_path
            opts["redirect_after_logout_uri"] = logout_redirect
        end
    end

    local function oidc_access_action()
        local action = ngx.var.oidc_access_action
        if action and action ~= "" then 
            -- action aliases
            action = (action == "allow" or action == "ignore" or action == "public") and "pass" or action
            action = (action == "deny" or action == "noauth") and "no-auth" or action
            return action 
        end
        for _, pattern in ipairs(cfg["auth_locations"] or {}) do
            if request_path:sub(1, string.len(pattern)) == pattern then
                return "auth"
            end
        end
        for _, pattern in ipairs(cfg["pass_locations"] or {}) do
            if request_path:sub(1, string.len(pattern)) == pattern then
                return "pass"
            end
        end
        for _, pattern in ipairs(cfg["no_auth_locations"] or cfg["noauth_locations"] or {}) do
            if request_path:sub(1, string.len(pattern)) == pattern then
                return "no-auth"
            end
        end
        return "auth"
    end
    local action = oidc_access_action()
    local res, err, url, session = require("resty.openidc").authenticate(opts, nil, (action == "pass" or action == "no-auth") and "pass", session_opts)
    if err then
        ngx.log(ngx.ERR, err)
        ngx.status = 500
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    local claims = res and {}
    if claims then
        if res["user"] then
            for k,v in pairs(res["user"]) do claims[k] = v end
        end
        if res["id_token"] then
            for k,v in pairs(res["id_token"]) do claims[k] = v end
        end
        if session.data["enc_id_token"] then
            claims["enc_id_token"] = session.data["enc_id_token"]
            claims["bearer_enc_id_token"] = "Bearer " .. session.data["enc_id_token"]
        end
        local str = require "resty.string"
        claims["session$id"] = str.to_hex(session.id)
    end

    if claims and cfg["enc_id_token"] and not claims["enc_id_token"] then
        claims = nil
    end
    if not claims and (action ~= "pass") then
        ngx.status = 401
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    for name,claim in pairs(cfg["claim_vars"] or {}) do
        ngx.var[name] = claims and claims[claim]
    end
    for name,claim in pairs(cfg["claim_headers"] or {}) do
        local claim_escape = claim:match("^(.+)%%$")
        local claim_val = claims and claims[claim_escape or claim]
        ngx.req.set_header(name, claim_val and claim_escape and ngx.escape_uri(claim_val) or claim_val)
    end
end
