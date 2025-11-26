# we need to do these shenanigans because we cannot pass variables conditionally to this module during tdd
locals {
  backup_image_base = var.backup_image_base == null ? "tobiashvmz/pve-cloud-backup" : var.backup_image_base
  backup_image_version = var.backup_image_version == null ? "0.5.0" : var.backup_image_version
}

variable "backup_image_version" {
  type = string
  description = "Backup image version, doesn't need to be changed usually."
  default = null
}

variable "backup_image_base" {
  type = string
  description = "Backup image base, doesn't need to be changed usually."
  default = null
}

variable "pve_host" {
  type = string
  description = "Single host of pve cluster"
}

variable "backup_config" {
  description = "Configuration for backup system"
  type = object({
    backup_daemon_address = string
    patroni_stack = string
    k8s_stacks = map(object({
      include_namespaces  = optional(list(string))
      exclude_namespaces  = optional(list(string))
    }))
    git_repos      = optional(list(string))
    nextcloud_files = optional(list(string))
  })
}

variable "bandwidth_limitation" {
  type = string
  description = "Bandwith limitation for ingress and egress. Prevent locking up the network through backups."
  default = "100M"
}

variable "cron_schedule" {
  type = string
  description = "How often the backup job should run"
  default = "0 0 * * 0,2,4,6" # This runs the job every second day
}

variable "k8s_master_ssh_key" {
  type = string
  description = "SSH private key that has access to proxmox k8s master vms of the pve cloud ecosystem."
}

variable "git_repo_ssh_key" {
  type = string
  description = "SSH private key for backing up git repos."
  default = null
}

variable "git_repo_ssh_key_type" {
  type = string
  description = "SSH private key type. Needs to be specified for ssh to autoload via ~/.ssh/id_..."
  default = "ed25519"
  validation {
    condition     = contains(["rsa", "ed25519", "ecdsa", "dsa"], var.git_repo_ssh_key_type)
    error_message = "The SSH key type must be one of: rsa, ed25519, ecdsa, dsa."
  }
}

variable "nextcloud_url" {
  type = string
  description = "URL of Nextcloud instance we want to backup files from"
  default = null
}

variable "nextcloud_pass" {
  type = string
  description = "Nextcloud password for accessing files."
  default = null
}

variable "nextcloud_user" {
  type = string
  description = "Nextcloud user login name."
  default = null
}

variable "qemu_admin_user" {
  type = string
  description = "user to login to pve cloud vms with"
  default = "admin"
}