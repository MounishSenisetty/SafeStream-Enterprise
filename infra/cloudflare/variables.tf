variable "account_id" {
  description = "Cloudflare account that owns the zone and the Workers/R2/D1/Pages resources."
  type        = string
}

variable "zone_name" {
  description = "The domain, already added to the account (it was registered through Cloudflare)."
  type        = string
  default     = "safestreamdata.com"
}

variable "zone_plan" {
  description = "Plan of the zone: free, pro, business or enterprise. Paid plans also get the Cloudflare Managed and OWASP rulesets; the free plan's own managed ruleset is always on."
  type        = string
  default     = "free"

  validation {
    condition     = contains(["free", "pro", "business", "enterprise"], var.zone_plan)
    error_message = "zone_plan must be free, pro, business or enterprise."
  }
}

variable "environments" {
  description = "Control-plane environments. Each gets its own D1 database and R2 buckets."
  type        = set(string)
  default     = ["staging", "production"]
}

variable "hsts_max_age" {
  description = "Strict-Transport-Security max-age in seconds. Browsers remember it for this long: raise it only once every subdomain is known to serve HTTPS."
  type        = number
  default     = 15552000 # 180 days
}

variable "hsts_preload" {
  description = "Add the preload directive. Only then can the domain be submitted to browsers' preload lists, which is very slow to undo."
  type        = bool
  default     = false
}

variable "audit_lock_days" {
  description = "Days an object in the production audit bucket cannot be deleted or overwritten. 0 turns the lock off. A lock cannot be shortened for objects already written."
  type        = number
  default     = 0
}

variable "api_rate_limit_per_10s" {
  description = "Requests one client IP may make to the API host in 10 seconds before it is blocked for 10 seconds."
  type        = number
  default     = 100
}
