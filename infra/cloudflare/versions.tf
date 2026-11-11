terraform {
  required_version = ">= 1.9"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.28"
    }
  }

  # State lives in an R2 bucket (S3-compatible). The bucket and the endpoint are
  # passed at init time, because they contain the account id:
  #   terraform init -backend-config="bucket=safestream-tfstate" \
  #     -backend-config="endpoints={s3=\"https://<account id>.r2.cloudflarestorage.com\"}"
  # with an R2 API token in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.
  backend "s3" {
    key                         = "cloudflare/terraform.tfstate"
    region                      = "auto"
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}

# Reads CLOUDFLARE_API_TOKEN from the environment.
provider "cloudflare" {}
