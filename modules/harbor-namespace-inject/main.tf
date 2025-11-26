variable "namespace" {
  type = string
}

variable "dockerconfig" {
  type = string
}

resource "kubernetes_secret" "pull_secret" {
  type = "kubernetes.io/dockerconfigjson"
  metadata {
    namespace = var.namespace 
    name = "cluster-pull-secret"
  }

  data = {
    ".dockerconfigjson" = var.dockerconfig
  }
}


resource "kubernetes_default_service_account" "default" {
  metadata {
    namespace = var.namespace
  }
  image_pull_secret {
    name = kubernetes_secret.pull_secret.metadata[0].name
  }
}
