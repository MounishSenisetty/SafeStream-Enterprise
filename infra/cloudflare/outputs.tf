output "zone_id" {
  value = local.zone_id
}

output "name_servers" {
  description = "Cloudflare name servers for the zone."
  value       = data.cloudflare_zone.this.name_servers
}

output "dnssec_ds_record" {
  description = "DS record. Published automatically when Cloudflare is the registrar."
  value       = cloudflare_zone_dnssec.this.ds
}

output "site_pages_subdomain" {
  value = cloudflare_pages_project.site.subdomain
}

output "d1_database_ids" {
  description = "D1 database id per environment, for the control plane's wrangler configuration."
  value       = { for env, db in cloudflare_d1_database.control_plane : env => db.id }
}

output "r2_buckets" {
  value = {
    for env in var.environments : env => {
      policies = cloudflare_r2_bucket.policies[env].name
      audit    = cloudflare_r2_bucket.audit[env].name
    }
  }
}
