resource "kubernetes_namespace" "pve_cloud_controller" {
  metadata {
    name = "pve-cloud-controller"
  }
}

locals {
  default_exclude_adm_namespaces = [
    "default", "kube-system", "kube-public", 
    "kube-node-lease", "pve-cloud-controller", 
    "nginx-ingress", "ceph-csi", "pve-cloud-backup",
    "pve-cloud-monitoring-master", "pve-cloud-monitoring-client"
  ]
}

# optionally create mirror pull secret
resource "kubernetes_secret" "mirror_pull_secret" {
  count = var.harbor_mirror_host != null && var.harbor_mirror_auth != null ? 1 : 0
  metadata {
    namespace = kubernetes_namespace.pve_cloud_controller.metadata[0].name
    name = "mirror-pull-secret"
  }
  data = {
    ".dockerconfigjson" = <<-EOT
        {
                "auths": {
                        "${var.harbor_mirror_host}": {
                                "auth": "${var.harbor_mirror_auth}"
                        }
                }
        }
    EOT
  }
  type = "kubernetes.io/dockerconfigjson"
}

resource "kubernetes_manifest" "watcher" {
  manifest = yamldecode(<<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: pve-cloud-watcher
      namespace: ${kubernetes_namespace.pve_cloud_controller.metadata[0].name}
      labels:
        app.kubernetes.io/name: pve-cloud-watcher
        app.kubernetes.io/version: '${local.cloud_controller_version}'
    spec:
      replicas: 1
      selector:
        matchLabels:
          app.kubernetes.io/name: pve-cloud-watcher
      template:
        metadata:
          labels:
            app.kubernetes.io/name: pve-cloud-watcher
            app.kubernetes.io/version: '${local.cloud_controller_version}'
        spec:
          containers:
            - name: watcher
              image: "${local.cloud_controller_image}:${local.cloud_controller_version}"
              imagePullPolicy: IfNotPresent
              env:
                - name: STACK_FQDN
                  value: '${var.k8s_stack_fqdn}'
                - name: PG_CONN_STR
                  value: '${var.pg_conn_str}'
                - name: EXCLUDE_BASE_NAMESPACES
                  value: '${join(",", local.default_exclude_adm_namespaces)}'
      %{ if var.harbor_mirror_host != null && var.harbor_mirror_auth != null }
                - name: HARBOR_MIRROR_HOST
                  value: '${var.harbor_mirror_host}'
                - name: HARBOR_MIRROR_PULL_SECRET_NAME
                  value: 'mirror-pull-secret'
      %{ endif }
              command: [ "watcher" ]
  YAML
  )
}

resource "kubernetes_manifest" "adm_deployment" {
  manifest = yamldecode(<<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: pve-cloud-adm
      namespace: ${kubernetes_namespace.pve_cloud_controller.metadata[0].name}
      labels:
        app.kubernetes.io/name: pve-cloud-adm
        app.kubernetes.io/version: '${local.cloud_controller_version}'
    spec:
      replicas: 2
      selector:
        matchLabels:
          app.kubernetes.io/name: pve-cloud-adm
      template:
        metadata:
          labels:
            app.kubernetes.io/name: pve-cloud-adm
            app.kubernetes.io/version: '${local.cloud_controller_version}'
        spec:
          volumes:
            - name: pve-cloud-adm-tls
              secret:
                secretName: pve-cloud-adm-tls
                items:
                  - key: tls.crt
                    path: tls.crt
                  - key: tls.key
                    path: tls.key
          containers:
            - name: adm
              image: "${local.cloud_controller_image}:${local.cloud_controller_version}"
              imagePullPolicy: IfNotPresent
              volumeMounts:
                - name: pve-cloud-adm-tls
                  mountPath: "/etc/tls"  
                  readOnly: true
              env:
                - name: PG_CONN_STR
                  value: '${var.pg_conn_str}'
                - name: EXCLUDE_ADM_NAMESPACES
                  value: '${join(",", concat(local.default_exclude_adm_namespaces, var.exclude_adm_webhook_namespaces))}'
      %{ if var.harbor_mirror_host != null && var.harbor_mirror_auth != null }
                - name: HARBOR_MIRROR_HOST
                  value: '${var.harbor_mirror_host}'
                - name: HARBOR_MIRROR_PULL_SECRET_NAME
                  value: 'mirror-pull-secret'
      %{ endif }
      %{ if var.bind_master_ip != null && var.bind_dns_update_key != null && var.internal_proxy_floating_ip != null }
                - name: BIND_MASTER_IP
                  value: '${var.bind_master_ip}'
                - name: BIND_DNS_UPDATE_KEY
                  value: '${var.bind_dns_update_key}'
                - name: INTERNAL_PROXY_FIP
                  value: '${var.internal_proxy_floating_ip}' 
      %{ endif}
      %{ if var.route53_access_key_id != null && var.route53_secret_access_key != null && var.external_forwarded_ip != null }
                - name: ROUTE53_REGION
                  value: '${var.route53_region}'
                - name: ROUTE53_ACCESS_KEY_ID
                  value: '${var.route53_access_key_id}'
                - name: ROUTE53_SECRET_ACCESS_KEY
                  value: '${var.route53_secret_access_key}'
                - name: EXTERNAL_FORWARDED_IP
                  value: '${var.external_forwarded_ip}'     
      %{ endif}
      %{ if var.route53_endpoint_url != null }
                - name: ROUTE53_ENDPOINT_URL
                  value: '${var.route53_endpoint_url}'
      %{ endif}
              command: [ "adm" ]
              ports:
                - name: https
                  containerPort: 443
                  protocol: TCP
  YAML
  )
}

resource "kubernetes_manifest" "adm_service" {
  manifest = yamldecode(<<-YAML
    apiVersion: v1
    kind: Service
    metadata:
      name: pve-cloud-adm
      namespace: ${kubernetes_namespace.pve_cloud_controller.metadata[0].name}
    spec:
      type: ClusterIP
      ports:
        - port: 443
          targetPort: https
          protocol: TCP
          name: https
      selector:
          app.kubernetes.io/name: pve-cloud-adm

  YAML
  )
}

resource "kubernetes_mutating_webhook_configuration" "adm_hook" {
  metadata {
    name = "pve-cloud-adm"
  }

  webhook {
    name = "pod.pve-cloud-adm.pve.cloud"

    client_config {
      service {
        name      = "pve-cloud-adm"
        namespace = kubernetes_namespace.pve_cloud_controller.metadata[0].name
        path      = "/mutate-pod"
        port      = 443
      }
      ca_bundle = tls_self_signed_cert.ca.cert_pem
    }

    rule {
      api_groups   = [""]
      api_versions = ["v1"]
      operations   = ["CREATE"]
      resources    = ["pods"]
    }

    # hook patch for pods should not trigger for all namespaces
    namespace_selector {
      match_expressions {
        key = "kubernetes.io/metadata.name"
        operator = "NotIn"
        values = concat(local.default_exclude_adm_namespaces, var.exclude_adm_webhook_namespaces)
      }
    }

    admission_review_versions = ["v1"]
    side_effects              = "None"
    failure_policy            = "Fail"
  }
  
  webhook {
    name = "ingress-dns.pve-cloud-adm.pve.cloud"

    client_config {
      service {
        name      = "pve-cloud-adm"
        namespace = kubernetes_namespace.pve_cloud_controller.metadata[0].name
        path      = "/ingress-dns"
        port      = 443
      }
      ca_bundle = tls_self_signed_cert.ca.cert_pem
    }

    rule {
      api_groups   = ["networking.k8s.io"]
      api_versions = ["v1"]
      operations   = ["CREATE", "UPDATE", "DELETE"] # dynamic dns record 
      resources    = ["ingresses"]
    }

    # ingress dns for everything
    namespace_selector {}

    admission_review_versions = ["v1"]
    side_effects              = "None"
    failure_policy            = "Fail"
  }

}


resource "kubernetes_manifest" "cron" {
  manifest = yamldecode(<<-YAML
    apiVersion: batch/v1
    kind: CronJob
    metadata:
      name: pve-cloud-cron
      namespace: ${kubernetes_namespace.pve_cloud_controller.metadata[0].name}
      labels:
        app.kubernetes.io/name: pve-cloud-cron
        app.kubernetes.io/version: '${local.cloud_controller_version}'
    spec:
      schedule: "0 0 * * *"  # once every night
      jobTemplate:
        spec:
          backoffLimit: 0
          template:
            metadata:
              labels:
                app.kubernetes.io/name: pve-cloud-cron
                app.kubernetes.io/version: '${local.cloud_controller_version}'
            spec:
              restartPolicy: Never
              containers:
                - name: cron
                  image: "${local.cloud_controller_image}:${local.cloud_controller_version}"
                  imagePullPolicy: IfNotPresent
                  env:
                    - name: STACK_FQDN
                      value: '${var.k8s_stack_fqdn}'
                    - name: PG_CONN_STR
                      value: '${var.pg_conn_str}'
      %{ if var.harbor_mirror_host != null && var.harbor_mirror_auth != null }
                    - name: HARBOR_MIRROR_HOST
                      value: '${var.harbor_mirror_host}'
                    - name: HARBOR_MIRROR_PULL_SECRET_NAME
                      value: 'mirror-pull-secret'
      %{ endif }
      %{ if var.bind_master_ip != null && var.bind_dns_update_key != null && var.internal_proxy_floating_ip != null }
                    - name: BIND_MASTER_IP
                      value: '${var.bind_master_ip}'
                    - name: BIND_DNS_UPDATE_KEY
                      value: '${var.bind_dns_update_key}'
                    - name: INTERNAL_PROXY_FIP
                      value: '${var.internal_proxy_floating_ip}' 
      %{ endif}
      %{ if var.route53_access_key_id != null && var.route53_secret_access_key != null && var.external_forwarded_ip != null }
                    - name: ROUTE53_REGION
                      value: '${var.route53_region}'
                    - name: ROUTE53_ACCESS_KEY_ID
                      value: '${var.route53_access_key_id}'
                    - name: ROUTE53_SECRET_ACCESS_KEY
                      value: '${var.route53_secret_access_key}'
                    - name: EXTERNAL_FORWARDED_IP
                      value: '${var.external_forwarded_ip}'     
      %{ endif}
      %{ if var.route53_endpoint_url != null }
                    - name: ROUTE53_ENDPOINT_URL
                      value: '${var.route53_endpoint_url}'
      %{ endif}
                    - name: EXCLUDE_BASE_NAMESPACES
                      value: '${join(",", local.default_exclude_adm_namespaces)}'
                  command: [ "cron" ]
  YAML
  )
}

