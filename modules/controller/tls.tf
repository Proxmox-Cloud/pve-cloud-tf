# create the certificates
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "pve-cloud-adm-controller"
  }

  validity_period_hours = 876000  # 36500 days
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "key_encipherment",
    "digital_signature",
  ]
}

resource "tls_private_key" "server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name = "pve-cloud-adm.pve-cloud-controller.svc"
  }

  dns_names = [
    "pve-cloud-adm.pve-cloud-controller.svc",
    "pve-cloud-adm"
  ]
}


resource "tls_locally_signed_cert" "server" {
  cert_request_pem = tls_cert_request.server.cert_request_pem

  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 876000  # 36500 days

  allowed_uses = [
    "server_auth",
    "key_encipherment",
    "digital_signature",
  ]
}

# create k8s secret
resource "kubernetes_secret" "pve_cloud_adm_tls" {
  metadata {
    name      = "pve-cloud-adm-tls"
    namespace = kubernetes_namespace.pve_cloud_controller.metadata[0].name
  }

  type = "kubernetes.io/tls"

  data = {
    "tls.crt" = tls_locally_signed_cert.server.cert_pem
    "tls.key" = tls_private_key.server.private_key_pem
  }
}