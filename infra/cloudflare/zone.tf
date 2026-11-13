# The zone already exists (the domain was registered through Cloudflare), so it
# is looked up, never created or destroyed, by this configuration.
data "cloudflare_zone" "this" {
  filter = {
    name = var.zone_name
  }
}

locals {
  zone_id = data.cloudflare_zone.this.id
  # Production and staging control plane. One label deep, so the zone's
  # Universal SSL certificate covers both.
  api_hosts     = ["api.${var.zone_name}", "api-staging.${var.zone_name}"]
  api_host_expr = "http.host in {${join(" ", formatlist("\"%s\"", local.api_hosts))}}"
  site_host     = "docs.${var.zone_name}"
}

# DNSSEC. With Cloudflare as registrar the DS record is published automatically.
resource "cloudflare_zone_dnssec" "this" {
  zone_id = local.zone_id
  status  = "active"
}

# ---------------------------------------------------------------------------
# TLS: encrypt to the origin and verify it, modern protocol versions only,
# HTTPS everywhere.
# ---------------------------------------------------------------------------

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = local.zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = local.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = local.zone_id
  setting_id = "tls_1_3"
  value      = "on"
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = local.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "automatic_https_rewrites" {
  zone_id    = local.zone_id
  setting_id = "automatic_https_rewrites"
  value      = "on"
}

resource "cloudflare_zone_setting" "security_header" {
  zone_id    = local.zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      include_subdomains = true
      max_age            = var.hsts_max_age
      nosniff            = true
      preload            = var.hsts_preload
    }
  }
}
