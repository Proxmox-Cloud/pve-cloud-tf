# init core scenario
variable "test_pve_conf" {
  type = string
}

variable "pve_ansible_host" {
  type = string
}

variable "pve_cloud_pg_cstr" {
  type = string
}

variable "cloud_controller_image" {
  type = string
  default = null
}

variable "cloud_controller_version" {
  type = string
  default = null
}

locals {
  test_pve_conf = yamldecode(file(var.test_pve_conf))
}

# dev ingress dns
data "external" "bind_key" {
  program = ["bash", "-c", <<EOT
    ssh -o StrictHostKeyChecking=no root@${var.pve_ansible_host} base64 -w0 /etc/pve/cloud/secrets/internal.key | jq -Rc '{ b64: . }'
  EOT
  ]
}

module "controller" {
  source = "../../../modules/controller"
  pg_conn_str = var.pve_cloud_pg_cstr
  k8s_stack_fqdn = "pytest-k8s.${local.test_pve_conf["pve_test_cloud_domain"]}"

  bind_master_ip = local.test_pve_conf["pve_test_cloud_inv"]["bind_master_ip"]
  bind_dns_update_key = regex("secret\\s+\"([^\"]+)\";", base64decode(data.external.bind_key.result.b64))[0]
  internal_proxy_floating_ip = local.test_pve_conf["pve_test_cloud_inv_cluster"]["pve_haproxy_floating_ip_internal"]

  cloud_controller_image = var.cloud_controller_image
  cloud_controller_version = var.cloud_controller_version
  
  adm_controller_replicas = 1 # for easier log reading

  route53_access_key_id = "test"
  route53_secret_access_key = "test"
  external_forwarded_ip = "127.0.0.1" # test too
  route53_endpoint_url = "http://pve-cloud-moto:5000"

  cluster_cert_entries = [
    {
      zone = local.test_pve_conf["pve_test_deployments_domain"],
      names = ["*"]
    }
  ]
}

# deploy a moto server for testing external ingress dns
resource "kubernetes_manifest" "moto_deployment" {
  depends_on = [ module.controller ]
  manifest = yamldecode(<<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: pve-cloud-moto
      namespace: pve-cloud-controller
      labels:
        app.kubernetes.io/name: pve-cloud-moto
    spec:
      replicas: 1
      selector:
        matchLabels:
          app.kubernetes.io/name: pve-cloud-moto
      template:
        metadata:
          labels:
            app.kubernetes.io/name: pve-cloud-moto
        spec:
          containers:
            - name: moto
              image:  motoserver/moto:5.1.17
              imagePullPolicy: IfNotPresent
              ports:
                - name: http
                  containerPort: 5000
                  protocol: TCP
  YAML
  )
}

resource "kubernetes_manifest" "moto_service" {
  depends_on = [ module.controller ]
  manifest = yamldecode(<<-YAML
    apiVersion: v1
    kind: Service
    metadata:
      name: pve-cloud-moto
      namespace: pve-cloud-controller
    spec:
      type: NodePort
      ports:
        - port: 5000
          targetPort: http
          nodePort: 30500
          protocol: TCP
          name: http
      selector:
          app.kubernetes.io/name: pve-cloud-moto

  YAML
  )
}
