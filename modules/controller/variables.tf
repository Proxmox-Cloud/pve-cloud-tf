# we need to do these shenanigans because we cannot pass variables conditionally to this module during tdd
# the formatting has to stay exactly the same for the auto gitlab ci variables to be able to update the version
locals {
  cloud_controller_image = var.cloud_controller_image == null ? "tobiashvmz/pve-cloud-controller" : var.cloud_controller_image
  cloud_controller_version = var.cloud_controller_version == null ? "1.8.2" : var.cloud_controller_version
}

variable "cloud_controller_image" {
  type = string
  default = null
  description = "When set to non null value will use that insead of hardcoded image in locals."
}

variable "cloud_controller_version" {
  type = string
  default = null
  description = "Image version, normally hardcoded, only set in test cases."
}

variable "adm_controller_replicas" {
  type = number
  default = 2
}

variable "harbor_mirror_host" {
  type = string
  default = null
  description = "If set the cloud controller will use admission controller patches to use the specified harbor mirror."
}

variable "harbor_mirror_auth" {
  type = string
  default = null
  description = "Dockerconfig that will created and assigned to the pods."
}

variable "k8s_stack_fqdn" {
  type = string
  description = "Stack name of kubespray inv + '.' + pve cloud domain."
}

variable "pg_conn_str" {
  type = string
  description = "Postgres connection string to pve cloud patroni postgres service."
}

variable "exclude_adm_webhook_namespaces" {
  type = list(string)
  description = "Namespaces to exclude from admission controller patch."
  default = []
}

# ingress dns is mandatory, clean dns this way
variable "bind_master_ip" {
  type = string
}

variable "bind_dns_update_key" {
  type = string
}

variable "internal_proxy_floating_ip" {
  type = string
}

# route53 credentials, if specified this will enable external ingress dns
variable "route53_access_key_id" {
  type = string
  default = null
}

variable "route53_secret_access_key" {
  type = string
  default = null
}

variable "route53_region" {
  type = string
  default = "eu-central-1" 
}

variable "external_forwarded_ip" {
  type = string
  default = null
}

variable "cluster_cert_entries" {
  type = list(object({
    zone              = string
    names             = list(string)
    authoritative_zone = optional(bool, false)
    apex_zone_san      = optional(bool, false)
  }))
}

variable "external_domains" {
  type = list(object({
    zone              = string
    names             = list(string)
    expose_apex      = optional(bool, false)
  }))
}

# this is optional and used for e2e testing with moto aws mock
variable "route53_endpoint_url" {
  type = string
  default = null
}