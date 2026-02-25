# oidc-codeql-test

Testing GitHub Advanced CodeQL scanning with OIDC authentication to AWS CodeArtifact.

## Overview

This repository demonstrates:
1. **OIDC-based authentication** from GitHub Actions to AWS (no long-lived secrets)
2. **CodeQL Advanced Security scanning** on a Java application that depends on a private Maven artifact hosted in **AWS CodeArtifact**
3. Detection of **intentional vulnerabilities** across both the application and its private dependency

## Project Structure

```
oidc-codeql-test/
├── shared-utils/           # Custom Maven library (published to CodeArtifact)
│   ├── pom.xml
│   └── src/main/java/com/cback/sharedutils/
│       ├── InputSanitizer.java    # No-op sanitizer (CWE-20)
│       ├── XmlHelper.java         # XXE-vulnerable parser (CWE-611)
│       └── DatabaseHelper.java    # SQL concatenation (CWE-89)
├── vuln-app/               # Vulnerable application (depends on shared-utils)
│   ├── pom.xml
│   └── src/main/java/com/cback/vulnapp/
│       ├── App.java               # XXE via XmlHelper (CWE-611)
│       ├── UserController.java    # SQL injection + XSS (CWE-89, CWE-79)
│       ├── FileService.java       # Path traversal (CWE-22)
│       └── AuthService.java       # Hardcoded creds + weak crypto (CWE-798, CWE-327)
├── aws/                    # AWS IAM policy reference files
│   ├── trust-policy.json
│   └── codeartifact-read-policy.json
├── .github/workflows/
│   └── codeql.yml          # CodeQL workflow with OIDC → CodeArtifact auth
└── PLAN.md
```

## How It Works

1. The GitHub Actions workflow triggers on push/PR to `main`
2. It uses **OIDC** (`id-token: write`) to assume an AWS IAM role scoped to this repository
3. The assumed role fetches a short-lived **CodeArtifact auth token**
4. Maven `settings.xml` is configured with the token to resolve `com.cback:shared-utils:1.0.0`
5. **CodeQL** initializes, observes the Maven build, and analyzes all source code (including the resolved dependency)
6. Results are uploaded to the GitHub Security tab

## Setup

### Prerequisites
- AWS account with CodeArtifact domain `cback` and repository `codeql-test-repo`
- IAM OIDC identity provider for `token.actions.githubusercontent.com`
- IAM role `GitHubActions-CodeQL-Role` (see [aws/](aws/) for policy files)
- `shared-utils` published to CodeArtifact

### Publish shared-utils (one-time)

```bash
# Configure AWS credentials
aws configure  # or aws sso login

# Get CodeArtifact auth token
export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token \
  --domain cback --domain-owner 806414315277 --region us-east-1 \
  --query authorizationToken --output text)

# Configure Maven settings (~/.m2/settings.xml) — see PLAN.md Step 4-5

# Deploy
cd shared-utils
mvn deploy
```

### AWS IAM Setup

```bash
# Create OIDC provider (if not exists)
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Create role with trust policy
aws iam create-role \
  --role-name GitHubActions-CodeQL-Role \
  --assume-role-policy-document file://aws/trust-policy.json

# Attach permissions
aws iam put-role-policy \
  --role-name GitHubActions-CodeQL-Role \
  --policy-name CodeArtifactReadAccess \
  --policy-document file://aws/codeartifact-read-policy.json
```

## Expected CodeQL Findings

| Vulnerability              | Source File            | CWE     | Severity |
|---------------------------|------------------------|---------|----------|
| SQL Injection              | UserController.java    | CWE-89  | Critical |
| XXE                        | App.java / XmlHelper   | CWE-611 | High     |
| Cross-Site Scripting (XSS) | UserController.java    | CWE-79  | High     |
| Path Traversal             | FileService.java       | CWE-22  | High     |
| Hardcoded Credentials      | AuthService.java       | CWE-798 | Medium   |
| Weak Cryptography (MD5)    | AuthService.java       | CWE-327 | Medium   |
