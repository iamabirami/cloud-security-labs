output "cloudtrail_bucket" {
  description = "S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.trail.bucket
}

output "guardduty_detector_id" {
  description = "Detector ID, needed to generate sample findings."
  value       = aws_guardduty_detector.main.id
}

output "alerts_topic_arn" {
  description = "SNS topic that emails security alerts."
  value       = aws_sns_topic.alerts.arn
}
