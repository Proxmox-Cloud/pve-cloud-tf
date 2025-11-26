resource "kubernetes_deployment" "graphite_exporter" {
  metadata {
    name      = "graphite-exporter"
    namespace = helm_release.kube_prom_stack.namespace
    labels = {
      app = "graphite-exporter"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "graphite-exporter"
      }
    }

    template {
      metadata {
        labels = {
          app = "graphite-exporter"
        }
      }

      spec {
        container {
          name  = "graphite-exporter"
          image = "prom/graphite-exporter:latest"
          port {
            container_port = 9108
          }
          port {
            container_port = 9109
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "graphite_exporter_nodeport" {
  metadata {
    name      = "graphite-exporter-nodeport"
    namespace = helm_release.kube_prom_stack.namespace
  }

  spec {
    selector = {
      app = "graphite-exporter"
    }

    port {
      name = "graphite"
      protocol    = "TCP"
      port        = 9109
      target_port = 9109
      node_port   = 30109
    }

    type = "NodePort"
  }
}


resource "kubernetes_service" "graphite_exporter" {
  metadata {
    name      = "graphite-exporter-headless"
    namespace = helm_release.kube_prom_stack.namespace
  }

  spec {
    selector = {
      app = "graphite-exporter"
    }

    cluster_ip = "None"

    type = "ClusterIP"
  }
}
