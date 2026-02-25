# oidc-codeql-test

Demonstrates GitHub Advanced CodeQL scanning with OIDC authentication to AWS CodeArtifact.

## Overview

This repository shows how GitHub Actions can use **OIDC federation** to authenticate to AWS, fetch a private Maven dependency from **AWS CodeArtifact**, and run a **CodeQL Advanced Security scan** that depends on that dependency to build successfully.

The application (`vuln-app`) imports a custom library (`com.cback:shared-utils:1.0.0`) that only exists in CodeArtifact. Without OIDC auth, the Maven build fails and CodeQL produces minimal results, and likely throw a warning about code coverage not being complete.

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

> **Note:** The `shared-utils` library source code is intentionally **not** in this repository. It was published separately to CodeArtifact (`com.cback:shared-utils:1.0.0`). 

## How It Works

1. GitHub Actions workflow triggers on push/PR to `main`
2. OIDC (`id-token: write`) is used to assume an AWS IAM role scoped to `repo:chetbackiewicz/oidc-codeql-test:*`
3. The assumed role fetches a short-lived CodeArtifact auth token (short expiry)
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

Created the GitHub Actions OIDC identity provider

Created an IAM role with trust policy scoped to this repo

Attached CodeArtifact read-only permissions

The trust policy ensures only GitHub Actions workflows running **from this specific repository** can assume the role. The permissions are limited to CodeArtifact read operations.

### 4. Created the CodeQL workflow

## Outcome

The CodeQL scan successfully:
- Authenticated to AWS via OIDC (no stored secrets)
- Resolved `com.cback:shared-utils:1.0.0` from CodeArtifact
- Built `vuln-app` with the private dependency
- Detected **7 vulnerabilities** across the application

### CodeQL Reported 7 Findings