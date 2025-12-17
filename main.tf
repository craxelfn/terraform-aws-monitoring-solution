terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- 1. SNS Topic for Alerts (Day 2 Prep) ---
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts-topic"
}

resource "aws_sns_topic_subscription" "email_sub" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- 2. S3 Bucket for Frontend ---
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "frontend" {
  bucket        = "${var.project_name}-frontend-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_website_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  index_document { suffix = "index.html" }
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.frontend.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.frontend]
}

resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.frontend.id
  key          = "index.html"
  source       = "${path.module}/app/frontend/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/app/frontend/index.html")
}

# --- 3. Lambda Function (Backend) ---
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/app/backend/index.js"
  output_path = "${path.module}/app/backend/lambda.zip"
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_lambda_function" "api_backend" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-backend"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  tracing_config {
    mode = "Active"
  }
}

# --- 4. API Gateway ---
resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type"]
  }
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/api-gw/${var.project_name}"
  retention_in_days = 7
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
    format          = "$context.identity.sourceIp - - [$context.requestTime] \"$context.httpMethod $context.routeKey $context.protocol\" $context.status $context.responseLength $context.requestId"
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id           = aws_apigatewayv2_api.main.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.api_backend.invoke_arn
}

resource "aws_apigatewayv2_route" "post_route" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_backend.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name                = "${var.project_name}-backend-error-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "Errors"
  namespace                 = "AWS/Lambda"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "This alarm triggers when the Backend Lambda fails."
  insufficient_data_actions = []
  
  dimensions = {
    FunctionName = aws_lambda_function.api_backend.function_name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
}

# --- 5. CloudTrail Setup ---
# S3 Bucket for CloudTrail Logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.project_name}-cloudtrail-logs-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "delete-old-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.frontend.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# --- 6. EventBridge Rules for Operational Events ---

# IAM Role for EventBridge to invoke Lambda
resource "aws_iam_role" "eventbridge_lambda_role" {
  name = "${var.project_name}-eventbridge-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eventbridge_lambda_logs" {
  role       = aws_iam_role.eventbridge_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "eventbridge_lambda_sns" {
  name = "${var.project_name}-eventbridge-lambda-sns-policy"
  role = aws_iam_role.eventbridge_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sns:Publish"
      ]
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

# Lambda function for automated response
data "archive_file" "event_handler_zip" {
  type        = "zip"
  output_path = "${path.module}/app/backend/event_handler.zip"

  source {
    content  = <<-EOF
      exports.handler = async (event) => {
        const AWS = require('aws-sdk');
        const sns = new AWS.SNS();
        
        console.log('Received event:', JSON.stringify(event, null, 2));
        
        const detail = event.detail;
        const eventName = detail.eventName;
        const userIdentity = detail.userIdentity;
        const sourceIP = detail.sourceIPAddress;
        
        let message = `AWS Event Detected:\n`;
        message += `Event: $${eventName}\n`;
        message += `User: $${userIdentity.type} - $${userIdentity.principalId || 'N/A'}\n`;
        message += `Source IP: $${sourceIP}\n`;
        message += `Time: $${event.time}\n`;
        message += `Region: $${event.region}\n`;
        
        if (eventName.includes('Delete') || eventName.includes('Terminate')) {
          message += `\n⚠️  WARNING: This is a destructive operation!\n`;
        }
        
        await sns.publish({
          TopicArn: process.env.SNS_TOPIC_ARN,
          Subject: `AWS Event Alert: $${eventName}`,
          Message: message
        }).promise();
        
        return { statusCode: 200, body: 'Event processed' };
      };
    EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "event_handler" {
  filename         = data.archive_file.event_handler_zip.output_path
  function_name    = "${var.project_name}-event-handler"
  role             = aws_iam_role.eventbridge_lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  source_code_hash = data.archive_file.event_handler_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }
}

# EventBridge Rule: Monitor Lambda function configuration changes
resource "aws_cloudwatch_event_rule" "lambda_config_changes" {
  name        = "${var.project_name}-lambda-config-changes"
  description = "Capture Lambda function configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "UpdateFunctionConfiguration",
        "UpdateFunctionCode",
        "DeleteFunction",
        "CreateFunction"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_config_changes_target" {
  rule      = aws_cloudwatch_event_rule.lambda_config_changes.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.event_handler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_lambda_config" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_config_changes.arn
}

# EventBridge Rule: Monitor S3 bucket policy changes
resource "aws_cloudwatch_event_rule" "s3_policy_changes" {
  name        = "${var.project_name}-s3-policy-changes"
  description = "Capture S3 bucket policy changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_policy_changes_target" {
  rule      = aws_cloudwatch_event_rule.s3_policy_changes.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.event_handler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3_policy" {
  statement_id  = "AllowExecutionFromEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_policy_changes.arn
}

# EventBridge Rule: Monitor IAM changes
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.project_name}-iam-changes"
  description = "Capture IAM role and policy changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateRole",
        "DeleteRole",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_changes_target" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.event_handler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_iam" {
  statement_id  = "AllowExecutionFromEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_changes.arn
}

# EventBridge Rule: Monitor security group changes
resource "aws_cloudwatch_event_rule" "security_group_changes" {
  name        = "${var.project_name}-sg-changes"
  description = "Capture security group changes"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "security_group_changes_target" {
  rule      = aws_cloudwatch_event_rule.security_group_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# EventBridge Rule: Direct SNS notification for critical events
resource "aws_cloudwatch_event_rule" "root_account_usage" {
  name        = "${var.project_name}-root-account-usage"
  description = "Alert on root account usage"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_account_usage_target" {
  rule      = aws_cloudwatch_event_rule.root_account_usage.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}