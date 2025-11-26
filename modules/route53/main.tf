variable "external_domains" {
  description = "List of external domains grouped by zone with names"
  type = list(object({
    zone  = string
    names = list(string)
  }))
}

variable "public_ip" {
  type = string
}

locals {
    external_domains = merge(
    [
      for zone_obj in var.external_domains : {
        for name in zone_obj.names : "${name}.${zone_obj.zone}" => {
          zone = zone_obj.zone
          name = name
        }
      }
    ]...
  )
}

module "records" {
  source = "./record"
  for_each = local.external_domains
  zone = each.value.zone
  name = each.value.name
  public_ip = var.public_ip
}