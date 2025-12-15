output "frontend_url" {
  value = "https://${aws_cloudfront_distribution.cdn.domain_name}"
}

output "api_url" {
  value = "${aws_api_gateway_stage.prod.invoke_url}/hello"
}