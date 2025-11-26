variable "harbor_k8s_stack_fqdn" {
  type = string
}

variable "harbor_namespace" {
  type = string
  default = "harbor"
}

variable "harbor_permissions" {
  # description harbor permissions after harbor permissions terraform provider for robot account
  type = list(object({
    namespace = string # aka the project name, can also be *

    access = list(object({
      action   = string # *, pull, push, create, read, update, delete, list, operate, scanner-pull, stop
      effect   = optional(string, "allow") # deny
    }))
  }))
}

variable "scope_name" {
  type = string
}
