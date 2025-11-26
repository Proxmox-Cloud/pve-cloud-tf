terraform {
  backend "pg" {} # sourced entirely via .envrc
}

variable "master_kubeconfig_b64" {
  type = string
}

variable "master_ip" {
  type = string
}

locals {
  kubeconfig = yamldecode(base64decode(var.master_kubeconfig_b64))
}

provider "kubernetes" {
  client_certificate = base64decode(local.kubeconfig.users[0].user.client-certificate-data)
  client_key = base64decode(local.kubeconfig.users[0].user.client-key-data)
  host = "https://${var.master_ip}:6443" # connect to load balanced control plane
  cluster_ca_certificate = base64decode(local.kubeconfig.clusters[0].cluster.certificate-authority-data)
}

provider "helm" {
  kubernetes = {
    client_certificate = base64decode(local.kubeconfig.users[0].user.client-certificate-data)
    client_key = base64decode(local.kubeconfig.users[0].user.client-key-data)
    host = "https://${var.master_ip}:6443" # connect to load balanced control plane
    cluster_ca_certificate = base64decode(local.kubeconfig.clusters[0].cluster.certificate-authority-data)   
  }
}
