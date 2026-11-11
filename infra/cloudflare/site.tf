# The public site (landing page and documentation), built by CI with MkDocs and
# uploaded with "wrangler pages deploy". No Git integration: the repository is
# private and stays unconnected to Cloudflare.
resource "cloudflare_pages_project" "site" {
  account_id        = var.account_id
  name              = "safestream-site"
  production_branch = "main"
}

resource "cloudflare_pages_domain" "site" {
  for_each = toset([var.zone_name, local.www_host])

  account_id   = var.account_id
  project_name = cloudflare_pages_project.site.name
  name         = each.key
}

# One canonical address: www redirects to the apex.
resource "cloudflare_ruleset" "redirects" {
  zone_id     = local.zone_id
  name        = "Redirects"
  description = "www to apex"
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"

  rules = [
    {
      ref         = "www_to_apex"
      description = "www to apex"
      expression  = "(http.host eq \"${local.www_host}\")"
      action      = "redirect"
      action_parameters = {
        from_value = {
          status_code = 301
          target_url = {
            expression = "concat(\"https://${var.zone_name}\", http.request.uri.path)"
          }
          preserve_query_string = true
        }
      }
    }
  ]
}
