@"
# CloudSentinel-Lite

An event-driven serverless system for automated detection and remediation of AWS security misconfigurations.

## Rules
- Public S3 bucket
- Security group open to 0.0.0.0/0 on SSH
- IAM user without MFA

## Services
CloudTrail, EventBridge, Lambda, SQS, DynamoDB, SNS, CloudWatch, IAM, CloudFormation

## Team
- (add names and roles)
"@ | Set-Content README.md