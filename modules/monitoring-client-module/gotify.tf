# create app for cluster
resource "null_resource" "post_gotify_app" {
  provisioner "local-exec" {
    command = <<EOT
      curl -u 'admin:${var.gotify_admin_pw}' \
        -X POST https://${var.gotify_host}/application \
        -H "Content-Type: application/json" \
        -d '{"name":"${var.k8s_stack_name}"}'
    EOT
  }
}

# fetch application token
data "http" "gotify_apps" {
  depends_on = [ null_resource.post_gotify_app ]
  url = "https://${var.gotify_host}/application"

  request_headers = {
    Accept        = "application/json"
    Authorization = "Basic ${base64encode("admin:${var.gotify_admin_pw}")}"
  }
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
            value = "https://${var.gotify_host}/message"
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