# Contributing to Honeypot Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn and grow

## Getting Started

### Prerequisites
- Terraform >= 1.0
- Git
- Docker & Docker Compose (for ELK Stack)
- Python 3.8+

### Development Setup

```bash
git clone https://github.com/yourusername/honeypot-framework.git
cd honeypot-framework
terraform -chdir=terraform/environments/local init
```

## Development Workflow

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Follow the existing code style
- Test your changes locally
- Update documentation as needed

### 3. Commit Guidelines

Use conventional commits:
