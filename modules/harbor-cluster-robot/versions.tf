terraform {
  required_providers {
    harbor = {
      source = "goharbor/harbor"
      version = "3.11.0"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.36.0"
    }
  }
}
