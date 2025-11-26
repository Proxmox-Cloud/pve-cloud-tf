resource "harbor_robot_account" "account" {
  name        = var.scope_name
  description = "robot account for scope ${var.scope_name}"
  level       = "system"

  dynamic "permissions" {
    for_each = var.harbor_permissions
    content {
      kind = "project"
      namespace = permissions.value.namespace

      dynamic "access" {
        for_each = permissions.value.access
        content {
          resource = "repository"
          action = access.value.action
          effect = access.value.effect
        }
      }
    }
  }
}

output "robot_creds" {
  sensitive = true
  value = {
    full_name = harbor_robot_account.account.full_name
    secret = harbor_robot_account.account.secret
    dockerconfig =  <<-CFG
      {
              "auths": {
                      "${local.harbor_host}": {
                              "auth": "${base64encode("${harbor_robot_account.account.full_name}:${harbor_robot_account.account.secret}")}"
                      }
              }
      }
    CFG
  }
}
