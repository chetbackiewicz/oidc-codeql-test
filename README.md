# oidc-codeql-test

Demonstrates GitHub Advanced CodeQL scanning with OIDC authentication to AWS CodeArtifact — no long-lived secrets.

## Overview

This repository proves that GitHub Actions can use **OIDC federation** to authenticate to AWS, fetch a private Maven dependency from **AWS CodeArtifact**, and run a **CodeQL Advanced Security scan** that depends on that dependency to build successfully.

The application (`vuln-app`) imports a custom library (`com.cback:shared-utils:1.0.0`) that only exists in CodeArtifact. Without OIDC auth, the Maven build fails and CodeQL produces zero results.

## Project Structure

```
oidc-codeql-test/
├── vuln-app/                              # Vulnerable Java application
│   ├── pom.xml                            # Depends on shared-utils from CodeArtifact
│   └── src/main/java/com/cback/vulnapp/
│       ├── App.java                       # XXE via XmlHelper (CWE-611)
│       ├── UserController.java            # SQL injection, XSS, XXE, path traversal
│       ├── FileService.java               # Path traversal (CWE-22)
│       └── AuthService.java               # Hardcoded creds + weak crypto (CWE-798, CWE-327)
├── aws/                                   # IAM policy reference files
│   ├── trust-policy.json                  # OIDC trust scoped to this repo
│   └── codeartifact-read-policy.json      # CodeArtifact read-only permissions
├── .github/workflows/
│   └── codeql.yml                         # CodeQL workflow with OIDC → CodeArtifact auth
└── README.md
```

> **Note:** The `shared-utils` library source code is intentionally **not** in this repository. It was published separately to CodeArtifact (`com.cback:shared-utils:1.0.0`). This proves that the CodeQL scan requires registry access — without it, the build fails entirely.

## How It Works

1. GitHub Actions workflow triggers on push/PR to `main`
2. OIDC (`id-token: write`) is used to assume an AWS IAM role scoped to `repo:chetbackiewicz/oidc-codeql-test:*`
3. The assumed role fetches a short-lived CodeArtifact auth token (12-hour expiry)
4. Maven `settings.xml` is generated with the token to resolve `com.cback:shared-utils:1.0.0`
5. CodeQL initializes, traces the Maven build, and analyzes the compiled source
6. Results are uploaded to the GitHub Security tab

## Setup Steps Taken

### 1. Created the shared-utils library (published to CodeArtifact)

A small Java library with three intentionally vulnerable classes (`InputSanitizer`, `XmlHelper`, `DatabaseHelper`) was created locally, built with Maven, and deployed to CodeArtifact:

```
Domain:     cback
Repository: codeql-test-repo
Artifact:   com.cback:shared-utils:1.0.0
Region:     us-east-1
```

The source was then removed from this repo so the artifact is only available via CodeArtifact.

### 2. Created the vuln-app application

A Java application that depends on `shared-utils` and contains additional intentional vulnerabilities (SQL injection, XSS, XXE, path traversal, hardcoded credentials, weak cryptography). The `vuln-app/pom.xml` points to the CodeArtifact repository URL.

### 3. Configured AWS OIDC federation

```bash
# Created the GitHub Actions OIDC identity provider
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Created an IAM role with trust policy scoped to this repo
aws iam create-role \
  --role-name GitHubActions-CodeQL-Role \
  --assume-role-policy-document file://aws/trust-policy.json

# Attached CodeArtifact read-only permissions
aws iam put-role-policy \
  --role-name GitHubActions-CodeQL-Role \
  --policy-name CodeArtifactReadAccess \
  --policy-document file://aws/codeartifact-read-policy.json
```

The trust policy ensures only GitHub Actions workflows running **from this specific repository** can assume the role. The permissions are limited to CodeArtifact read operations.

### 4. Created the CodeQL workflow

The workflow (`.github/workflows/codeql.yml`) chains: OIDC assume-role → CodeArtifact token → Maven settings → `mvn compile` → CodeQL analyze.

## Outcome

The CodeQL scan successfully:
- Authenticated to AWS via OIDC (no stored secrets)
- Resolved `com.cback:shared-utils:1.0.0` from CodeArtifact
- Built `vuln-app` with the private dependency
- Detected **7 vulnerabilities** across the application

### CodeQL Findings

| Vulnerability | File | CWE | Severity |
|---|---|---|---|
| SQL Injection | UserController.java | CWE-89 | Critical |
| Cross-Site Scripting (XSS) | UserController.java | CWE-79 | High |
| XXE (XML External Entity) | UserController.java | CWE-611 | High |
| Path Traversal | UserController.java | CWE-22 | High |
| Information Exposure via Error | UserController.java | CWE-209 | Medium |
| Use of Broken Cryptographic Algorithm | AuthService.java | CWE-327/328 | Medium |
| Hardcoded Credentials | AuthService.java | CWE-798 | Medium |

## Security Note

This is a public repository. The following information is visible but **not exploitable**:

- **AWS Account ID** (`806414315277`) — Not a secret per AWS documentation. Grants no access on its own.
- **IAM Role ARN** — The role can only be assumed via OIDC by workflows running in **this specific repo**. Fork PRs cannot assume it (the `pull_request` trigger uses the fork's identity).
- **CodeArtifact URL** — Unauthenticated requests are rejected. The URL without a valid token is useless.
- **IAM policies in `aws/`** — These are reference copies showing the minimal read-only permissions. They reveal no credentials.

The role's trust policy uses `StringLike: "repo:chetbackiewicz/oidc-codeql-test:*"` — only GitHub Actions running from this exact repository can assume it.
