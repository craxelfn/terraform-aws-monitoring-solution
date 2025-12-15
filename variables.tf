variable "region" {
  default = "eu-west-3"
}

variable "project_name" {
  default = "obs-demo"
}

variable "alert_email" {
  description = "Email to receive alerts"
  type        = string
  default     = "oussamaa1lakrafi@gmail.com" 
}