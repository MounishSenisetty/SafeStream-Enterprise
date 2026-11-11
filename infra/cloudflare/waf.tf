# ---------------------------------------------------------------------------
# Edge security. The API host (the control plane, added in a later phase) is
# closed by default: only its published routes and methods get through, and
# one client cannot flood it. The rules are in place before the host exists.
# ---------------------------------------------------------------------------

resource "cloudflare_ruleset" "waf_custom" {
  zone_id     = local.zone_id
  name        = "Custom firewall rules"
  description = "Deny by default on the API host; drop scanner noise everywhere"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "api_unknown_route"
      description = "API: only published routes"
      expression  = "(http.host eq \"${local.api_host}\" and not starts_with(http.request.uri.path, \"/v1/\") and http.request.uri.path ne \"/healthz\")"
      action      = "block"
    },
    {
      ref         = "api_unknown_method"
      description = "API: only the methods the API uses"
      expression  = "(http.host eq \"${local.api_host}\" and not http.request.method in {\"GET\" \"POST\" \"PUT\"})"
      action      = "block"
    },
    {
      ref         = "scanner_noise"
      description = "Probes for files this site never serves"
      expression  = "(http.request.uri.path contains \"/.env\" or http.request.uri.path contains \"/.git/\" or http.request.uri.path contains \"/wp-login.php\" or http.request.uri.path contains \"/xmlrpc.php\")"
      action      = "block"
    },
  ]
}

# One rule, shaped to fit the free plan (10-second period and timeout, counted
# per IP and Cloudflare location). Paid plans can lengthen both.
resource "cloudflare_ruleset" "rate_limit" {
  zone_id     = local.zone_id
  name        = "Rate limits"
  description = "Per-client request ceiling on the API host"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "api_per_ip"
      description = "API: per-IP ceiling"
      expression  = "(http.host eq \"${local.api_host}\")"
      action      = "block"
      ratelimit = {
        characteristics     = ["ip.src", "cf.colo.id"]
        period              = 10
        requests_per_period = var.api_rate_limit_per_10s
        mitigation_timeout  = 10
      }
    }
  ]
}

# Paid plans only: the Cloudflare Managed Ruleset and the OWASP Core Ruleset.
# (The free plan's own managed ruleset is deployed by Cloudflare automatically.)
resource "cloudflare_ruleset" "waf_managed" {
  count = var.zone_plan == "free" ? 0 : 1

  zone_id     = local.zone_id
  name        = "Managed rulesets"
  description = "Cloudflare Managed and OWASP Core rulesets"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = [
    {
      ref         = "cloudflare_managed"
      description = "Cloudflare Managed Ruleset"
      expression  = "true"
      action      = "execute"
      action_parameters = {
        id = "efb7b8c949ac4650a09736fc376e9aee"
      }
    },
    {
      ref         = "owasp_core"
      description = "Cloudflare OWASP Core Ruleset"
      expression  = "true"
      action      = "execute"
      action_parameters = {
        id = "4814384a9e5d4991b9815dcfc25d2f1f"
      }
    },
  ]
}
