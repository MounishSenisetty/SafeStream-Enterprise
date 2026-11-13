# Cloudflare infrastructure for safestreamdata.com

Terraform for everything on the domain. Nothing here is applied from a laptop: the
`Deploy` workflow plans on pull requests and applies on `main` after approval.

## What it manages

| File | Resources |
|---|---|
| `zone.tf` | Looks up the existing zone; DNSSEC; TLS settings (Full strict, TLS 1.2+, TLS 1.3, HTTPS everywhere, HSTS) |
| `dns.tf` | CAA limited to Cloudflare's CAs; null MX, SPF `-all` and DMARC `reject` (the domain sends no mail, so nobody can spoof it); the site's records |
| `site.tf` | Pages project for the public site and its custom domain, `docs.safestreamdata.com`. The apex and `www` are served by a Worker managed outside this configuration, which also owns their redirect rules |
| `waf.tf` | Custom firewall rules (API host closed by default, scanner noise blocked), one rate-limit rule, managed rulesets on paid plans |
| `access.tf` | Cloudflare Access applications for the console hosts (`app`, `app-staging`) and the policy saying who may sign in (`console_allowed_emails`, `console_allowed_email_domains`; none by default, which keeps the console closed) |
| `storage.tf` | Per environment: a D1 database and R2 buckets for policy bundles and audit evidence; optional write-once lock on production audit evidence |

It does not create the zone (the domain was registered through Cloudflare) and will not
delete it. The control-plane Worker and its `api` and `api-staging` hosts are deployed by
Wrangler from `control-plane/`, and so are the console's `app` and `app-staging` hosts;
Access in front of those hosts is managed here (`access.tf`). Identity providers (each design
partner's OIDC or SAML IdP) and the Zero Trust team name are set up once in the Zero Trust
dashboard; put the team domain (`<team>.cloudflareaccess.com`) in the repository variable
`ACCESS_TEAM_DOMAIN`.

## One-time setup

1. **State bucket.** In the Cloudflare dashboard, create an R2 bucket named
   `safestream-tfstate` and an R2 API token with *Object Read & Write* on that bucket only.
2. **API token** for Terraform, scoped to this account and zone, with:
   Zone: *Zone Read*, *Zone Settings Edit*, *DNS Edit*, *Zone WAF Edit*, *Dynamic Redirect
   Edit*, *Workers Routes Edit*; Account: *Cloudflare Pages Edit*, *D1 Edit*, *Workers R2
   Storage Edit*, *Workers Scripts Edit*, *Access: Apps and Policies Edit*.
3. **GitHub**, under Settings → Secrets and variables → Actions:

   | Kind | Name | Value |
   |---|---|---|
   | Secret | `CLOUDFLARE_API_TOKEN` | the token from step 2 |
   | Secret | `CLOUDFLARE_ACCOUNT_ID` | the account id |
   | Secret | `TFSTATE_R2_ACCESS_KEY_ID`, `TFSTATE_R2_SECRET_ACCESS_KEY` | the R2 token from step 1 |
   | Secret | `CONTROL_PLANE_SECRETS_STAGING`, `CONTROL_PLANE_SECRETS_PRODUCTION` | see `control-plane/README.md` |
   | Variable | `CLOUDFLARE_ENABLED` | `true` |

4. **Approval.** Create a GitHub environment named `cloudflare` and add yourself as a
   required reviewer. Without one, pushes to `main` apply unattended.

## Before the first apply

Read the plan in the workflow log. Three things deserve a look on a live domain:

- **Existing DNS records.** Terraform adds records; it does not remove ones it did not
  create. An existing record with the same name and type (an apex `A`, an `MX`, an SPF `TXT`)
  makes the apply fail or conflict. Remove or import it first.
- **Mail.** The null MX, SPF `-all` and DMARC `reject` declare that this domain sends and
  receives no mail. If you already use it for mail, delete those three records from `dns.tf`
  before applying, or mail will be rejected.
- **HSTS.** Browsers remember it for `hsts_max_age` (180 days by default), for every
  subdomain. `hsts_preload` is off; turning it on is very slow to undo.

## Variables worth knowing

| Variable | Default | Meaning |
|---|---|---|
| `zone_plan` | `free` | `pro` or above also deploys the Cloudflare Managed and OWASP rulesets |
| `audit_lock_days` | `0` | Days production audit evidence cannot be deleted or overwritten. Cannot be shortened for objects already written |
| `api_rate_limit_per_10s` | `100` | Per-IP ceiling on the API host |
| `console_allowed_emails`, `console_allowed_email_domains` | none | Who Access lets through to the console. Each person still needs a role from a tenant admin |
| `console_identity_providers` | all | Zero Trust identity provider ids the console accepts |
| `console_session_duration` | `8h` | Console sign-in lifetime |
| `hsts_max_age`, `hsts_preload` | 180 days, `false` | See above |

Set them as `TF_VAR_<name>` in the workflow, or in a `terraform.tfvars` that holds no secrets.

## After the first apply

```bash
dig +short DS safestreamdata.com
```

```bash
dig +short TXT _dmarc.safestreamdata.com
```

Then check the TLS grade at SSL Labs and that `https://docs.safestreamdata.com` serves the
public site.
