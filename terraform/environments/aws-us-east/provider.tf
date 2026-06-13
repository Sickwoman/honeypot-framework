terraform {
  backend "s3" {
    # Configure these values or use -backend-config during init
    # bucket         = "honeypot-framework-tfstate-us-east-1"
    # key            = "terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "honeypot-framework-lock"
    # encrypt        = true
  }
}
