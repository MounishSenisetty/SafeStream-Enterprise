# ---------------------------------------------------------------------------
# Control-plane storage, one set per environment so staging can never touch
# production data. Nothing here ever holds record content: policies are rules,
# audit evidence is counts and hashes.
# ---------------------------------------------------------------------------

resource "cloudflare_d1_database" "control_plane" {
  for_each = var.environments

  account_id = var.account_id
  name       = "safestream-${each.key}"
}

resource "cloudflare_r2_bucket" "policies" {
  for_each = var.environments

  account_id = var.account_id
  name       = "safestream-${each.key}-policies"
}

resource "cloudflare_r2_bucket" "audit" {
  for_each = var.environments

  account_id = var.account_id
  name       = "safestream-${each.key}-audit"
}

# Write-once audit evidence in production: objects cannot be deleted or
# overwritten until they are this old. Off until audit_lock_days is set.
resource "cloudflare_r2_bucket_lock" "audit" {
  count = var.audit_lock_days > 0 && contains(var.environments, "production") ? 1 : 0

  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.audit["production"].name
  rules = [
    {
      id      = "retain-audit-evidence"
      enabled = true
      condition = {
        type            = "Age"
        max_age_seconds = var.audit_lock_days * 86400
      }
    }
  ]
}
