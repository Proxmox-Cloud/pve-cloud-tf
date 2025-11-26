locals {
  # get all pve clusters in our cloud
  pve_inventory = yamldecode(file("${pathexpand("~/.pve-cloud-dyn-inv.yaml")}"))[var.pve_cloud_domain]

  # get ips grouped by pve cluster (for finding online hosts dynamically)
  ips_per_pve = {for pve_cluster, pve_hosts in local.pve_inventory : pve_cluster => [for pve_host, pve_hostvars in pve_hosts : pve_hostvars.ansible_host]}
}

data "external" "pve_vms" {
  for_each = local.ips_per_pve
  program = ["bash", "-c", <<EOT
    FIRST_ONLINE_PVE_HOST_IP=""
    for ip in ${join(" ", each.value)}; do
        if timeout 2 bash -c "</dev/tcp/$ip/22" &>/dev/null; then
          FIRST_ONLINE_PVE_HOST_IP=$ip
          break
        fi
    done

    ssh -o StrictHostKeyChecking=no root@$FIRST_ONLINE_PVE_HOST_IP pvesh get /cluster/resources --type vm --output-format json | base64 -w0 | jq -Rc '{ b64: . }'
  EOT
  ]
}

locals {
  # merge all pvesh api query results together
  pve_vm_api_response = flatten([for cluster, api_result in data.external.pve_vms: jsondecode(base64decode(api_result.result.b64))])

  # prefilter terraform if stream is stupid
  vms_with_tags = [
    for vm in local.pve_vm_api_response : vm
    if contains(keys(vm), "tags")
  ]

  systemd_mon_vms = [for vm in local.vms_with_tags : {
    name = vm.name
    stack_domain = one([for tag in split(";", vm.tags) : tag if contains(var.systemd_mon_stack_fqdns, tag)])
  } if anytrue([for stack_fqdn in var.systemd_mon_stack_fqdns : strcontains(vm.tags, stack_fqdn)])]

  stack_domains = distinct([for vm in local.systemd_mon_vms : vm.stack_domain])

  systemd_mon_vms_grouped = tomap({
    for domain in local.stack_domains :
    domain => [
      for vm in local.systemd_mon_vms : vm if vm.stack_domain == domain
    ]
  })
}


resource "helm_release" "kube_prom_stack" {
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"

  name             = "kube-prometheus-stack"
  namespace        = "pve-cloud-monitoring-master"
  create_namespace = true

  version = "72.3.1"

  values = [
    # scrape configs for all lxcs / vms that expose systemd prometheus exporter
    yamlencode({
      prometheus = {
        prometheusSpec = {
          additionalScrapeConfigs = concat([
            {
              job_name = "vms-systemd"
              static_configs = [
                for stack_domain, vms in local.systemd_mon_vms_grouped : {
                  targets = [
                    for mon_vm in vms : "${mon_vm.name}.${join(".", slice(split(".", mon_vm.stack_domain), 1, length(split(".", mon_vm.stack_domain))))}:9558"
                  ]
                  labels = {
                    "stack" = stack_domain
                  }
                }
              ]
            },
            {
              job_name = "pve-systemd"
              static_configs = flatten([
                for pve_cluster, pve_hosts in local.pve_inventory : [
                  for host, host_values in pve_hosts : {
                    targets = [ "${host_values.ansible_host}:9558" ]
                    labels = {
                      "host" = "${host}.${pve_cluster}"
                      "optional" = contains(var.optional_scrape_hosts, "${host}.${pve_cluster}")
                    }
                  }
                ]
              ])
            },
            {
              job_name = "pve-node"
              static_configs = flatten([
                for pve_cluster, pve_hosts in local.pve_inventory : [
                  for host, host_values in pve_hosts : {
                    targets = [ "${host_values.ansible_host}:9100" ]
                    labels = {
                      "host" = "${host}.${pve_cluster}"
                      "optional" = contains(var.optional_scrape_hosts, "${host}.${pve_cluster}")
                    }
                  }
                ]
              ])
            },
            {
              job_name = "pve-metrics"
              dns_sd_configs = [
                {
                  names = [ "graphite-exporter-headless.pve-cloud-monitoring-master.svc.cluster.local" ]
                  type = "A"
                  port = 9108
                }
              ]
            }
          ], 
          # conditional awx scrape target
          var.awx_user == null || var.awx_pass == null ? [] :
          [
            {
              job_name = "awx-metrics"
              metrics_path = "/api/v2/metrics"
              basic_auth = {
                username = var.awx_user
                password = var.awx_pass
              }
              # lower intervals cause duplicate entry errors in prometheus. this is a bug in awx https://github.com/ansible/awx/issues/15179
              # todo: lower / remove interval when fixxed
              scrape_interval = "5m"
              scheme = "http"
              static_configs = [
                {
                  targets = [
                    "awx-service.${var.awx_namespace}.svc.cluster.local:80"
                  ]
                }
              ]
            }
          ],
          var.extra_scrape_configs
          )
        }
      }
    }),
    # additional rules based on our custom scrape targets
    yamlencode({
      # disable default TargetDown rule, implement own that allows for optional scrape targets
      defaultRules = {
        disabled = {
          TargetDown = true
        }
      }
      additionalPrometheusRulesMap = merge({
        "default-override" = {
          groups = [
            {
              name = "override"
              rules = [
                {
                  alert = "TargetDown"
                  "for" = "10m"
                  expr = "100 * (count by (cluster, job, namespace, service) (up{optional!=\"true\"} == 0) / count by (cluster, job, namespace, service) (up{optional!=\"true\"})) > 10"
                  annotations = {
                    summary = "One or more targets are unreachable."
                    description = "	{{ printf \"%.4g\" $value }}% of the {{ $labels.job }}/{{ $labels.service }} targets in {{ $labels.namespace }} namespace are down."
                  }
                  labels = {
                    severity = "warning"
                  }
                }
              ]
            }
          ]
        }
        "pve-cloud-rules" = {
          groups = [
            {
              name = "awx"
              rules = [
                {
                  alert = "awx job failed"
                  "for" = "1m"
                  expr = "awx_status_total{status=\"failed\"} > 0"
                  labels = {
                    severity = "critical"
                  }
                  annotations = {
                    summary = "One or more AWX jobs have failed."
                    description = "A total of {{ $value }} jobs have failed."
                  }
                }
              ]
            },
            {
              name = "systemd"
              rules = [
                {
                  alert = "systemd service failed"
                  "for" = "1m"
                  expr = "systemd_unit_state{state=\"failed\"} == 1"
                  labels = {
                    severity = "critical"
                  }
                  annotations = {
                    summary = "Systemd service {{ $labels.name }} in stack {{ $labels.stack }} failed."
                    description = "Instance {{ $labels.instance }} systemd service {{ $labels.name }} entered failed state."
                  }
                }
              ]
            },
            {
              name = "pve-node"
              rules = var.enable_temperature_rules ? [
                {
                  alert = "cpu temperature high"
                  "for" = "1m"
                  expr = "node_hwmon_temp_celsius{chip=~\".*coretemp.*\"} > ${var.cpu_temperature_warn}"
                  labels = {
                    severity = "critical"
                  }
                  annotations = {
                    summary = "CPU temp of {{ $labels.host }} - {{ $labels.sensor }} is high."
                    description = "CPU temperature is at {{ $value }} of {{ $labels.host }} - sensor {{ $labels.sensor }}."
                  }
                },
                {
                  alert = "thermal zone temperature high"
                  "for" = "1m"
                  expr = "node_hwmon_temp_celsius{chip=~\".*thermal.*\"} > ${var.thermal_temperature_warn}"
                  labels = {
                    severity = "critical"
                  }
                  annotations = {
                    summary = "Thermal zone temp {{ $labels.host }} - {{ $labels.sensor }} is high."
                    description = "Thermal zone temperature is at {{ $value }} of {{ $labels.host }} - sensor {{ $labels.sensor }}."
                  }
                },
                {
                  alert = "disk temperature high"
                  "for" = "1m"
                  expr = "smartmon_temperature_celsius_raw_value > ${var.disk_temperature_warn}"
                  labels = {
                    severity = "critical"
                  }
                  annotations = {
                    summary = "Disk temp of {{ $labels.instance }} - {{ $labels.disk }} is high."
                    description = "Disk temperature is at {{ $value }} of {{ $labels.host }} - disk {{ $labels.disk }}."
                  }
                }
              ] : []
            }
          ]
        }
      },
      var.extra_alert_rules)
    }),
    # alertmanager settings
    yamlencode({
      alertmanager = {
        ingress = {
          enabled = var.alertmanger_e2e_ingress
          ingressClassName = "nginx"
          hosts = [
            "alertmgr.${var.ingress_apex}"
          ]
        }
        config = {
          route = {
            group_by = ["alertname", "job", "namespace", "stack", "host"]
            group_wait = "5s" # send almost instantly
            group_interval = "10s"
            repeat_interval = "999h" # alerts are never resend, keep gotify clean
            receiver = "gotify"
            routes = [
              {
                receiver = "null"
                matchers = [
                  "alertname = \"Watchdog\"" # dont send default watchdog alert => pipe to null receiver
                ]
              }
            ]
          }
          receivers = [
            {
              name = "gotify"
              webhook_configs = [
                {
                  url = "http://alertmanager-gotify.pve-cloud-monitoring-master.svc.cluster.local/gotify_webhook" # internal service
                  send_resolved = false
                }
              ]
            },
            {
              # null receiver like /dev/null
              name = "null"
            }
          ]
        }
      }
    })
  ]
}

output "namespace" {
  value = helm_release.kube_prom_stack.namespace
}
