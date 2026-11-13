# The public site (landing page and documentation), built by CI with MkDocs and
# uploaded with "wrangler pages deploy". No Git integration: the repository is
# private and stays unconnected to Cloudflare.
resource "cloudflare_pages_project" "site" {
  account_id        = var.account_id
  name              = "safestream-site"
  production_branch = "main"
}

# On its own host: the apex and www belong to a Worker managed outside this
# configuration, which also owns any redirects between them.
resource "cloudflare_pages_domain" "site" {
  account_id   = var.account_id
  project_name = cloudflare_pages_project.site.name
  name         = local.site_host
}
