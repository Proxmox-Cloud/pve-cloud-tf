terraform {
  required_providers {
    external = {
      source = "hashicorp/external"
      version = "2.3.5"
    }
    helm = {
      source = "hashicorp/helm"
      version = "3.1.1"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.36.0"
    }
    http = {
      source = "hashicorp/http"
      version = "3.5.0"
    }
    null = {
      source = "hashicorp/null"
      version = "3.2.4"
    }
    time = {
      source = "hashicorp/time"
      version = "0.13.1"
    }
  }
}