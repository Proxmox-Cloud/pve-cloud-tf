variable "test_pve_conf" {
  type = string
}

variable "pve_ansible_host" {
  type = string
}

variable "pve_cloud_pg_cstr" {
  type = string
}

variable "backup_image_base" {
  type = string
  default = null
}

variable "backup_image_version" {
  type = string
  default = null
}

locals {
  test_pve_conf = yamldecode(file(var.test_pve_conf))
}

# in this the unit test will make modifications
module "backup_source" {
  source = "./deployment"
  namespace = "test-backup-source"
}

# same deployment that will serve as the restore target namespace
module "backup_restore" {
  source = "./deployment"
  namespace = "test-backup-restore"
}

# slurp the automation key
data "external" "automation_key" {
  program = ["bash", "-c", <<EOT
    ssh -o StrictHostKeyChecking=no root@${var.pve_ansible_host} cat /etc/pve/cloud/automation_id_ed25519 | base64 -w0 | jq -Rc '{ b64: . }'
  EOT
  ]
}

module "tf_backup"{
  source =  "../../../modules/backup"
  pve_host = var.pve_ansible_host
  backup_config = {
    backup_daemon_address = "main-pytest-backup-lxc.${local.test_pve_conf["pve_test_cloud_domain"]}"
    patroni_stack = "ha-postgres.${local.test_pve_conf["pve_test_cloud_domain"]}"
    k8s_stacks = {
      "pytest-k8s.${local.test_pve_conf["pve_test_cloud_domain"]}" = {
        include_namespaces = [
          "test-backup-source"
        ]
      }
    }
  }

  k8s_master_ssh_key = base64decode(data.external.automation_key.result.b64)

  bandwidth_limitation = "20M"

  backup_image_base = var.backup_image_base
  backup_image_version = var.backup_image_version
}