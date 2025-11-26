resource "kubernetes_manifest" "controller_access_binding" {
  manifest = yamldecode(<<-YAML
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: pve-cloud-controller-binding
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      # todo: proper access rights
      name: cluster-admin
    subjects:
      - kind: ServiceAccount
        name: default
        namespace: ${kubernetes_namespace.pve_cloud_controller.metadata[0].name}
  YAML
  )
}