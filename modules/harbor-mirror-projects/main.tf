# google
resource "harbor_registry" "github_mirror" {
  provider_name = "docker-registry"
  name = "github ghcr"
  endpoint_url = "https://ghcr.io"
}

resource "harbor_project" "github_mirror" {
  name        = "github-mirror"
  registry_id = harbor_registry.github_mirror.registry_id
}

# aws
resource "harbor_registry" "aws_ecr_mirror" {
  provider_name = "docker-registry"
  name = "aws ecr"
  endpoint_url = "https://public.ecr.aws"
}

resource "harbor_project" "aws_ecr_mirror" {
  name        = "aws-ecr-mirror"
  registry_id = harbor_registry.aws_ecr_mirror.registry_id
}

# quay
resource "harbor_registry" "quay_mirror" {
  provider_name = "docker-registry"
  name = "quay"
  endpoint_url = "https://quay.io"
}

resource "harbor_project" "quay_mirror" {
  name        = "quay-mirror"
  registry_id = harbor_registry.quay_mirror.registry_id
}

# docker hub
resource "harbor_registry" "docker_hub_mirror" {
  provider_name = "docker-hub"
  name = "docker hub"
  endpoint_url = "https://hub.docker.com"
}

resource "harbor_project" "docker_hub_mirror" {
  name        = "docker-hub-mirror"
  registry_id = harbor_registry.docker_hub_mirror.registry_id
}