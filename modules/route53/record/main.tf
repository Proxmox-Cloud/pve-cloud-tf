
variable "name" {
  type = string
}
variable "zone" {
  type = string
}
variable "public_ip" {
  type = string
}

data "aws_route53_zone" "target_zone" {
  name         = var.zone
}

resource "aws_route53_record" "record"{
  zone_id = data.aws_route53_zone.target_zone.zone_id
  name   = var.name
  type   = "A"
  ttl    = "300"
  
  records = [var.public_ip]
}