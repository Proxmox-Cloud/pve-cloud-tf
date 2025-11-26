variable "pve_ansible_host" {
  type = string
}

variable "k8s_stack_name" {
  type = string
}

variable "systemd_mon_stack_fqdns" {
  type = list(string)
  default = []
}

variable "ingress_apex" {
  type = string
}

variable "pve_cloud_domain" {
  type = string
}

variable "awx_user" {
  type = string
  default = null
}

variable "awx_pass" {
  type = string
  default = null
}

variable "awx_namespace" {
  type = string
  default = "awx"
}

variable "enable_temperature_rules" {
  type = bool
  default = false
}

variable "cpu_temperature_warn" {
  type = number
  default = 60
}

variable "thermal_temperature_warn" {
  type = number
  default = 50
}

variable "disk_temperature_warn" {
  type = number
  default = 50
}

variable "optional_scrape_hosts" {
  type = list(string)
  default = []
}

variable "extra_scrape_configs" {
  type = list(any)
  default = []
}

variable "extra_alert_rules" {
  type = any
  default = {}
}

variable "external_karma_alertmanagers" {
  type = list(any)
  default = []
  description = "For backwards compatibility and intergrating systems that dont use the client-stack."
}

variable "insecure_tls" {
  type = bool
  default = false
  description = "For testing purposes."
}

variable "alertmanger_e2e_ingress" {
  type = bool
  default = false
  description = "Toggle alertmanager ingress for testing purposes."
}