

data "external" "kubeconfig" {
  # this script finds the first master that is online and gets its kubeconfig via ssh
  program = ["bash", "-c", <<EOT
    IP_LIST=$(dig +short "masters-${var.harbor_k8s_stack_fqdn}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

    FIRST_ONLINE_MASTER_IP=""
    for ip in $IP_LIST; do
        if timeout 2 bash -c "</dev/tcp/$ip/6443" &>/dev/null; then
          FIRST_ONLINE_MASTER_IP=$ip
        fi
    done

    ssh -o StrictHostKeyChecking=no admin@$FIRST_ONLINE_MASTER_IP sudo base64 -w0 /etc/kubernetes/admin.conf | jq -Rc '{ b64: . }'
  EOT
  ]
}

locals {
  kubeconfig = yamldecode(base64decode(data.external.kubeconfig.result.b64))
}

provider "kubernetes" {
  client_certificate = base64decode(local.kubeconfig.users[0].user.client-certificate-data)
  client_key = base64decode(local.kubeconfig.users[0].user.client-key-data)
  host = "https://control-plane-${var.harbor_k8s_stack_fqdn}:6443" # connect to load balanced control plane
  cluster_ca_certificate = base64decode(local.kubeconfig.clusters[0].cluster.certificate-authority-data)
}

data "kubernetes_secret" "harbor_creds" {
  metadata {
    name = "harbor-core"
    namespace = var.harbor_namespace
  }
}

data "kubernetes_ingress_v1" "harbor_ingress" {
  metadata {
    name = "harbor-ingress"
    namespace = var.harbor_namespace
  }
}

locals {
  harbor_host = data.kubernetes_ingress_v1.harbor_ingress.spec[0].rule[0].host
}

provider "harbor" {
  url = "https://${local.harbor_host}"
  username = "admin"
  password = data.kubernetes_secret.harbor_creds.data["HARBOR_ADMIN_PASSWORD"]
}