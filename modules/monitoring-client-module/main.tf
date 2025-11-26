
resource "kubernetes_secret" "basic_auth_secret" {
  type = "Opaque"
  metadata {
    name = "basic-auth"
    namespace = helm_release.kube_prom_stack.namespace
  }
  data = {
    "auth" : "karma:${bcrypt(var.alertmanager_basic_pw)}"
  }
}

resource "helm_release" "kube_prom_stack" {
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"

  name             = "kube-prometheus-stack"
  namespace        = "pve-cloud-monitoring-client"
  create_namespace = true

  version = "72.3.1"

  values = [
    yamlencode({
      alertmanager = {
        # expose alertmanager via ingress for karma in master stack to fetch
        ingress = {
          annotations = {
            "nginx.ingress.kubernetes.io/auth-type" = "basic"
            "nginx.ingress.kubernetes.io/auth-secret" = "basic-auth"
            "nginx.ingress.kubernetes.io/auth-realm" = "Authentication Required" 
          }
          ingressClassName = "nginx"
          enabled = true
          hosts = [
            var.alertmanager_host
          ]
          paths = [
            "/"
          ]
          tls = [
            {
              secretName = "cluster-tls"
              hosts = [
                var.alertmanager_host
              ]
            }
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
                  url = "http://alertmanager-gotify.pve-cloud-monitoring-client.svc.cluster.local/gotify_webhook" # internal service
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