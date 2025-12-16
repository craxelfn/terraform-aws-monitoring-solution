variable "region" {
  description = "AWS Region to deploy to"
  default     = "eu-west-3" 
}

variable "project_name" {
  description = "Base name for resources"
  default     = "obs-demo"
}

variable "alert_email" {
  description = "Email to receive alerts "
  type        = string
  default     = "oussamaa1lakrafi@gmail.com" 
}