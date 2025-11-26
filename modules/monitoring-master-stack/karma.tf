
resource "kubernetes_config_map" "karma" {
  metadata {
    name = "karma-conf"
    namespace = helm_release.kube_prom_stack.namespace
  }

  data = {
    "karma.yaml" = yamlencode({
      alertmanager = {
        interval = "5s"
        servers = concat([
          {
            name = var.k8s_stack_name
            uri = "http://kube-prometheus-stack-alertmanager.${helm_release.kube_prom_stack.namespace}.svc.cluster.local:9093"
            proxy = true
            healthcheck = {
              # filters out the default watchdog alert
              filters = {
                "pve-cloud-monitoring-master/kube-prometheus-stack-prometheus" = [ "alertname=Watchdog" ]
              }
            }
          }
        ], var.external_karma_alertmanagers)
      }
      # ui settings, custom colors and severity labels
      ui = {
        refresh = "10s"
        multiGridLabel = "severity"
      }
      grid = {
        sorting = {
          order = "label"
          reverse = false
          label = "serverity"
          customValues = {
            labels = {
              severity = {
                critical = 1
                warning = 2
                info = 3
              }
            }
          }
        }
      }
      labels = {
        color = {
          custom = {
            severity = [
              {
                value = "info"
                color = "#87c4e0"
              },
              {
                value = "warning"
                color = "#ffae42"
              },
              {
                value = "critical"
                color = "#ff220c"
              }
            ]
          }
        }
      }
    })
  }
}


resource "kubernetes_manifest" "karma" {
  manifest = yamldecode(<<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: karma
      namespace: ${helm_release.kube_prom_stack.namespace}
      labels:
        app: karma
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: karma
      template:
        metadata:
          labels:
            app: karma
        spec:
          containers:
            - name: karma
              image: ghcr.io/prymitive/karma:latest
              ports:
                - containerPort: 8080
              volumeMounts:
                - name: karma-config
                  mountPath: /karma-conf
              env:
                - name: CONFIG_FILE
                  value: /karma-conf/karma.yaml
          volumes:
            - name: karma-config
              configMap:
                name: karma-conf

  YAML
  )
}

resource "kubernetes_service" "karma" {
  metadata {
    name = "karma"
    namespace = helm_release.kube_prom_stack.namespace
  }
  spec {
    selector = {
      app = "karma"
    }

    port {
      port        = 80
      target_port = 8080
    }

    type = "ClusterIP"
  }
}