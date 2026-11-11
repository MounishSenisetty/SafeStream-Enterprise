# ---------------------------------------------------------------------------
# Certificate authorities. Only the CAs Cloudflare issues from may issue for
# this domain (Universal SSL and Pages custom domains use these three).
# ---------------------------------------------------------------------------

resource "cloudflare_dns_record" "caa" {
  for_each = toset(["letsencrypt.org", "pki.goog", "ssl.com"])

  zone_id = local.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 3600
  data = {
    flags = 0
    tag   = "issue"
    value = each.key
  }
  comment = "Only Cloudflare's certificate authorities may issue for this domain"
}

# ---------------------------------------------------------------------------
# Email. The domain neither sends nor receives mail, and says so, which stops
# anyone spoofing it: no mail servers (null MX), no permitted senders (SPF),
# reject on failure (DMARC). To start using mail, replace these three records
# (for Cloudflare Email Routing: cloudflare_email_routing_dns adds MX and SPF).
# ---------------------------------------------------------------------------

resource "cloudflare_dns_record" "null_mx" {
  zone_id  = local.zone_id
  name     = var.zone_name
  type     = "MX"
  ttl      = 3600
  content  = "."
  priority = 0
  comment  = "Null MX (RFC 7505): this domain accepts no mail"
}

resource "cloudflare_dns_record" "spf" {
  zone_id = local.zone_id
  name    = var.zone_name
  type    = "TXT"
  ttl     = 3600
  content = "\"v=spf1 -all\""
  comment = "No server may send mail as this domain"
}

resource "cloudflare_dns_record" "dmarc" {
  zone_id = local.zone_id
  name    = "_dmarc.${var.zone_name}"
  type    = "TXT"
  ttl     = 3600
  content = "\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
  comment = "Receivers must reject mail that fails SPF/DKIM alignment"
}

# ---------------------------------------------------------------------------
# Website (Cloudflare Pages). Proxied CNAMEs: the apex is flattened by Cloudflare.
# ---------------------------------------------------------------------------

resource "cloudflare_dns_record" "site" {
  for_each = toset([var.zone_name, local.www_host])

  zone_id = local.zone_id
  name    = each.key
  type    = "CNAME"
  ttl     = 1 # automatic; required for proxied records
  content = cloudflare_pages_project.site.subdomain
  proxied = true
  comment = "Public site on Cloudflare Pages"
}
