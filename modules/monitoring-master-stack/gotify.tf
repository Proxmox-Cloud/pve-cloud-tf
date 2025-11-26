resource "random_password" "gotify_admin_pw" {
  length           = 16
  special          = true
}

resource "helm_release" "gotify" {
  repository = "https://pmoscode-helm.github.io/gotify/"
  chart = "gotify"
  version = "0.5.2"
  name = "gotify"
  namespace = helm_release.kube_prom_stack.namespace

  values = [
    <<-EOT
      server:
        defaultUserPassword: '${random_password.gotify_admin_pw.result}'
      persistence:
        enabled: true
      ingress:
        className: nginx
        enabled: true
        hosts:
          - host: gotify.${var.ingress_apex}
            paths:
              - path: /
                pathType: ImplementationSpecific
        tls:
          - hosts:
              - gotify.${var.ingress_apex}
            secretName: cluster-tls
    EOT
  ]
}

# gotify startup time
resource "time_sleep" "gotify_startup" {
  depends_on = [ helm_release.gotify ]

  create_duration = "60s"
}

# create first app
resource "null_resource" "post_gotify_app" {
  depends_on = [ time_sleep.gotify_startup ]
  provisioner "local-exec" {
    command = <<EOT
      curl -u 'admin:${random_password.gotify_admin_pw.result}' ${var.insecure_tls ? "-k" : ""} \
        -X POST https://gotify.${var.ingress_apex}/application \
        -H "Content-Type: application/json" \
        -d '{"name":"${var.k8s_stack_name}"}'
    EOT
  }
}

# fetch application token
data "http" "gotify_apps" {
  depends_on = [ null_resource.post_gotify_app ]
  url = "https://gotify.${var.ingress_apex}/application"

  request_headers = {
    Accept        = "application/json"
    Authorization = "Basic ${base64encode("admin:${random_password.gotify_admin_pw.result}")}"
  }
  insecure = var.insecure_tls
}

# converts alertmanager receiver hook format to gotify post
resource "kubernetes_deployment" "alertmanager_gotify_bridge" {
  metadata {
    name      = "alertmanager-gotify"
    namespace = helm_release.kube_prom_stack.namespace
    labels = {
      app = "alertmanager-gotify"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "alertmanager-gotify"
      }
    }

    template {
      metadata {
        labels = {
          app = "alertmanager-gotify"
        }
      }

      spec {
        container {
          name  = "alertmanager-gotify"
          image = "druggeri/alertmanager_gotify_bridge:latest"
          port {
            container_port = 8080
          }
          env {
            name  = "GOTIFY_ENDPOINT"
            value = "https://gotify.${var.ingress_apex}/message"
          }
          env {
            name  = "GOTIFY_TOKEN"
            value = one([for app in jsondecode(data.http.gotify_apps.response_body): app.token if app.name == "${var.k8s_stack_name}"])
          }
        }
      }
    }
  }
}


resource "kubernetes_service" "alertmanager_gotify" {
  metadata {
    name      = "alertmanager-gotify"
    namespace = helm_release.kube_prom_stack.namespace
  }

  spec {
    selector = {
      app = "alertmanager-gotify"
    }

    port {
      protocol    = "TCP"
      port        = 80
      target_port = 8080
    }

    type = "ClusterIP"
  }
}

output "gotify_admin_pw" {
  value = nonsensitive(random_password.gotify_admin_pw.result)
}
