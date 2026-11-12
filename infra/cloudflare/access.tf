# ---------------------------------------------------------------------------
# Cloudflare Access in front of the console (app. and app-staging.). People
# sign in with an identity provider configured in Zero Trust (each design
# partner's own, via OIDC or SAML); nobody stores a password with us.
#
# Two locks, either of which keeps the console closed:
#   1. Access lets in only the emails and domains below (none by default:
#      then the application has no allow policy and lets nobody in).
#   2. The Worker verifies Access's signed token itself, for this
#      application's audience only, and maps the email to a tenant and role
#      in its own console_users table. Being let in by Access shows no data
#      by itself; a tenant admin must grant it.
# ---------------------------------------------------------------------------

locals {
  console_hosts = {
    production = "app.${var.zone_name}"
    staging    = "app-staging.${var.zone_name}"
  }

  console_allowed = length(var.console_allowed_emails) + length(var.console_allowed_email_domains) > 0
}

resource "cloudflare_zero_trust_access_policy" "console" {
  count = local.console_allowed ? 1 : 0

  account_id = var.account_id
  name       = "SafeStream console users"
  decision   = "allow"

  include = concat(
    [for email in var.console_allowed_emails : { email = { email = email } }],
    [for domain in var.console_allowed_email_domains : { email_domain = { domain = domain } }],
  )

  session_duration = var.console_session_duration
}

resource "cloudflare_zero_trust_access_application" "console" {
  for_each = { for env in var.environments : env => local.console_hosts[env] }

  account_id                 = var.account_id
  name                       = "SafeStream console (${each.key})"
  type                       = "self_hosted"
  domain                     = each.value
  destinations               = [{ type = "public", uri = each.value }]
  session_duration           = var.console_session_duration
  allowed_idps               = length(var.console_identity_providers) > 0 ? var.console_identity_providers : null
  app_launcher_visible       = false
  http_only_cookie_attribute = true
  same_site_cookie_attribute = "lax"

  policies = local.console_allowed ? [
    { id = cloudflare_zero_trust_access_policy.console[0].id, precedence = 1 }
  ] : []
}
