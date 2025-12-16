output "api_url" {
  value = aws_apigatewayv2_stage.default.invoke_url
  description = "Paste this into frontend/index.html"
}

output "website_url" {
  value = "http://${aws_s3_bucket_website_configuration.frontend.website_endpoint}"
  description = "Visit this URL to test the app"
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
  description = "Use this ARN for Day 2 Alarms"
}