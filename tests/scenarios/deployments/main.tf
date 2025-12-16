# init core scenario
variable "test_pve_conf" {
  type = string
}

variable "pve_ansible_host" {
  type = string
}

variable "pve_inventory_b64" {
  type = string
}

variable "pve_cloud_pg_cstr" {
  type = string
}

variable "nginx_rnd_hostname" {
  type = string
}

locals {
  test_pve_conf = yamldecode(file(var.test_pve_conf))
}

resource "helm_release" "nginx_test" {
  repository = "https://charts.bitnami.com/bitnami"
  chart = "nginx"
  version = "22.0.11"
  create_namespace = true
  namespace = "nginx-test"
  
  name = "nginx"

  values = [
    <<-YAML
      service:
        type: ClusterIP
      ingress:
        enabled: true
        hostname: ${var.nginx_rnd_hostname}.${local.test_pve_conf["pve_test_deployments_domain"]}
        tls: true
        selfSigned: true
        ingressClassName: nginx
    YAML
  ]
}

resource "helm_release" "nginx_external_test" {
  repository = "https://charts.bitnami.com/bitnami"
  chart = "nginx"
  version = "22.0.11"
  create_namespace = true
  namespace = "nginx-external-test"
  
  name = "nginx"

  values = [
    <<-YAML
      service:
        type: ClusterIP
      ingress:
        enabled: true
        hostname: external-example.${local.test_pve_conf["pve_test_deployments_domain"]}
        tls: true
        selfSigned: true
        ingressClassName: nginx
    YAML
  ]
}


module "tf_monitoring" {
  source = "../../../modules/monitoring-master-stack"
  pve_ansible_host = var.pve_ansible_host
  systemd_mon_stack_fqdns = [
    "ha-dhcp.${local.test_pve_conf["pve_test_cloud_domain"]}",
    "ha-bind.${local.test_pve_conf["pve_test_cloud_domain"]}",
    "ha-postgres.${local.test_pve_conf["pve_test_cloud_domain"]}",
    "ha-haproxy.${local.test_pve_conf["pve_test_cloud_domain"]}",
    "pytest-backup-lxc.${local.test_pve_conf["pve_test_cloud_domain"]}"
  ]
  k8s_stack_name = "pytest-k8s.${local.test_pve_conf["pve_test_cloud_domain"]}"
  ingress_apex = local.test_pve_conf["pve_test_deployments_domain"]
  pve_cloud_domain = local.test_pve_conf["pve_test_cloud_domain"]

  enable_temperature_rules = true

  thermal_temperature_warn = lookup(local.test_pve_conf["pve_test_tf_parameters"], "thermal_temperature_warn", 50)

  # for testing
  insecure_tls = true
  alertmanger_e2e_ingress = true
  pve_inventory_b64 = var.pve_inventory_b64
}

# expose karma directly
resource "kubernetes_manifest" "karma_ingress" {
  depends_on = [ module.tf_monitoring ]
  manifest = yamldecode(<<-YAML
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: karma-ingress
      namespace: pve-cloud-monitoring-master
    spec:
      ingressClassName: nginx
      rules:
        - host: karma.${local.test_pve_conf["pve_test_deployments_domain"]}
          http:
            paths:
              - path: /
                pathType: ImplementationSpecific
                backend:
                  service:
                    name: karma
                    port:
                      number: 80  
  YAML
  )
} 



# whitelist source ingress test (proxy protocol)
resource "helm_release" "nginx_test_proto" {
  repository = "https://charts.bitnami.com/bitnami"
  chart = "nginx"
  version = "22.0.11"
  create_namespace = true
  namespace = "nginx-test-prxy-proto"
  
  name = "nginx"

  values = [
    <<-YAML
      service:
        type: ClusterIP
      ingress:
        enabled: true
        annotations:
          nginx.ingress.kubernetes.io/whitelist-source-range: '127.0.0.1/32'
        hostname: nginx-test-prxy-proto.${local.test_pve_conf["pve_test_deployments_domain"]}
        tls: true
        selfSigned: true
        ingressClassName: nginx
    YAML
  ]
}
