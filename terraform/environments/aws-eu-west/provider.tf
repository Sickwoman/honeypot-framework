terraform {
  backend "s3" {
    # Configure these values or use -backend-config during init
    # bucket         = "honeypot-framework-tfstate-eu-west-1"
    # key            = "terraform.tfstate"
    # region         = "eu-west-1"
    # dynamodb_table = "honeypot-framework-lock"
    # encrypt        = true
  }
}
