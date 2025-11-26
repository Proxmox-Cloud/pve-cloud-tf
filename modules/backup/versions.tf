terraform {
  required_providers {
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.36.0"
    }
    external = {
      source = "hashicorp/external"
      version = "2.3.5"
    }
  }
}

