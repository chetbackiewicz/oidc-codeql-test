# Implementation Plan: OIDC + CodeQL + AWS CodeArtifact

## Objective

Build a test repository that demonstrates GitHub Advanced CodeQL scanning on a **purposefully vulnerable Java application** whose build depends on a **custom Maven artifact** hosted in **AWS CodeArtifact**. The CodeQL workflow authenticates to CodeArtifact using **OIDC** (no long-lived secrets), proving that the scan can resolve private dependencies and detect vulnerabilities in both the application code and the fetched artifact.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Repository: chetbackiewicz/oidc-codeql-test         │
│                                                             │
│  ┌──────────────────┐   ┌──────────────────────────────┐    │
│  │ Custom Library   │   │ Vulnerable Web App            │    │
│  │ (shared-utils)   │──▶│ (vuln-app) depends on         │    │
│  │ Published to     │   │ shared-utils from CodeArtifact│    │
│  │ CodeArtifact     │   └──────────────────────────────┘    │
│  └──────────────────┘                                       │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ .github/workflows/codeql.yml                         │   │
│  │  1. OIDC → AWS STS → assume role                     │   │
│  │  2. Get CodeArtifact auth token                      │   │
│  │  3. Configure Maven settings.xml                     │   │
│  │  4. CodeQL init → build (mvn) → analyze              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  AWS Account 806414315277                                   │
│                                                             │
│  ┌────────────────────────────────────────┐                 │
│  │ IAM OIDC Identity Provider             │                 │
│  │  Provider: token.actions.github...     │                 │
│  │  Audience: sts.amazonaws.com           │                 │
│  └────────────────────────────────────────┘                 │
│                                                             │
│  ┌────────────────────────────────────────┐                 │
│  │ IAM Role: GitHubActions-CodeQL-Role    │                 │
│  │  Trust: repo:chetbackiewicz/oidc-...   │                 │
│  │  Permissions:                          │                 │
│  │   - codeartifact:GetAuthorizationToken │                 │
│  │   - codeartifact:ReadFromRepository    │                 │
│  │   - sts:GetServiceBearerToken          │                 │
│  └────────────────────────────────────────┘                 │
│                                                             │
│  ┌────────────────────────────────────────┐                 │
│  │ CodeArtifact Domain: cback             │                 │
│  │  Repository: codeql-test-repo          │                 │
│  │  URL: https://cback-806414315277.d...  │                 │
│  └────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Create the Custom Maven Artifact (shared-utils)

**Goal:** Publish a small Java library to CodeArtifact that contains both utility methods _and_ intentionally vulnerable code (e.g., an unsafe XML parser, an insecure deserialization helper). This ensures CodeQL's scan is incomplete if it cannot resolve and analyze this dependency.

### 1.1 — Scaffold the library project

Create a Maven module: `shared-utils/`

```
shared-utils/
├── pom.xml
└── src/main/java/com/cback/sharedutils/
    ├── InputSanitizer.java      # Intentionally broken sanitizer (no-op or regex bypass)
    ├── XmlHelper.java           # XXE-vulnerable XML parsing
    └── DatabaseHelper.java      # SQL concatenation helper (SQL injection sink)
```

**pom.xml highlights:**
- `groupId`: `com.cback`
- `artifactId`: `shared-utils`
- `version`: `1.0.0`
- `<distributionManagement>` pointing to `cback-codeql-test-repo` CodeArtifact URL

### 1.2 — Implement intentionally vulnerable code

| Class                 | Vulnerability                                  | CWE                                |
| --------------------- | ---------------------------------------------- | ---------------------------------- |
| `InputSanitizer.java` | Returns input unchanged (pretends to sanitize) | CWE-20 (Improper Input Validation) |
| `XmlHelper.java`      | Parses XML with external entities enabled      | CWE-611 (XXE)                      |
| `DatabaseHelper.java` | Builds SQL via string concatenation            | CWE-89 (SQL Injection)             |

### 1.3 — Publish to CodeArtifact (manual, one-time)

```bash
# Get auth token
export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token \
  --domain cback --domain-owner 806414315277 --region us-east-1 \
  --query authorizationToken --output text)

# Create/update ~/.m2/settings.xml with server credentials
# Then publish
cd shared-utils
mvn deploy
```

**Deliverables:** `com.cback:shared-utils:1.0.0` available in CodeArtifact.

---

## Phase 2: Create the Vulnerable Application (vuln-app)

**Goal:** A Java web application that depends on `shared-utils` and uses its vulnerable methods, plus introduces additional vulnerabilities of its own.

### 2.1 — Scaffold the application project

```
vuln-app/
├── pom.xml
└── src/main/java/com/cback/vulnapp/
    ├── App.java                 # Entry point
    ├── UserController.java      # HTTP endpoint with injection flaws
    ├── FileService.java         # Path traversal vulnerability
    └── AuthService.java         # Hardcoded credentials, weak crypto
```

**pom.xml highlights:**
- `groupId`: `com.cback`
- `artifactId`: `vuln-app`
- `version`: `1.0.0`
- Dependency on `com.cback:shared-utils:1.0.0`
- Repository pointing to CodeArtifact URL (so Maven can resolve the dependency)
- Dependencies: `javax.servlet-api`, `commons-io`, etc.

### 2.2 — Implement intentionally vulnerable code

| Class                 | Vulnerability                                                              | CWE              |
| --------------------- | -------------------------------------------------------------------------- | ---------------- |
| `UserController.java` | Uses `DatabaseHelper.buildQuery()` from shared-utils → SQL injection       | CWE-89           |
| `UserController.java` | Uses `InputSanitizer.sanitize()` (which is a no-op) before rendering → XSS | CWE-79           |
| `FileService.java`    | Path traversal: user-controlled filename passed to `new File()`            | CWE-22           |
| `AuthService.java`    | Hardcoded password, uses `MD5` for hashing                                 | CWE-798, CWE-327 |
| `App.java`            | Calls `XmlHelper.parse()` from shared-utils with user XML → XXE            | CWE-611          |

### 2.3 — Why this requires the artifact

Without resolving `shared-utils` from CodeArtifact:
- CodeQL cannot trace data flows through `DatabaseHelper.buildQuery()` or `InputSanitizer.sanitize()`
- The XXE vulnerability in `XmlHelper` won't be detected since the source code isn't available
- Build will fail entirely (`mvn compile` needs the dependency)

This proves the OIDC → CodeArtifact auth is essential for a complete scan.

---

## Phase 3: AWS OIDC Configuration

**Goal:** Allow GitHub Actions to assume an IAM role via OIDC and access CodeArtifact.

### 3.1 — Create IAM OIDC Identity Provider (if not already done)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 3.2 — Create IAM Role with trust policy

**Trust Policy (`trust-policy.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::806414315277:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:chetbackiewicz/oidc-codeql-test:*"
        }
      }
    }
  ]
}
```

### 3.3 — Create IAM permissions policy

**Permissions Policy (`codeartifact-read-policy.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codeartifact:GetAuthorizationToken",
        "codeartifact:GetRepositoryEndpoint",
        "codeartifact:ReadFromRepository"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:GetServiceBearerToken",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "sts:AWSServiceName": "codeartifact.amazonaws.com"
        }
      }
    }
  ]
}
```

### 3.4 — Create the role

```bash
aws iam create-role \
  --role-name GitHubActions-CodeQL-Role \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name GitHubActions-CodeQL-Role \
  --policy-name CodeArtifactReadAccess \
  --policy-document file://codeartifact-read-policy.json
```

**Deliverable:** An IAM role ARN (e.g., `arn:aws:iam::806414315277:role/GitHubActions-CodeQL-Role`) that GitHub Actions can assume.

---

## Phase 4: GitHub Actions CodeQL Workflow

**Goal:** An advanced CodeQL setup workflow that authenticates to AWS via OIDC, configures Maven to pull from CodeArtifact, builds the project, and runs CodeQL analysis.

### 4.1 — Workflow file: `.github/workflows/codeql.yml`

```yaml
name: "CodeQL Advanced Scan"

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '30 6 * * 1'

permissions:
  id-token: write       # Required for OIDC
  contents: read        # Required for actions/checkout
  security-events: write # Required for uploading CodeQL results
  actions: read         # Required for private repo workflows

jobs:
  analyze:
    name: Analyze Java
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        language: ['java-kotlin']

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      # OIDC: Assume AWS role (no secrets needed)
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::806414315277:role/GitHubActions-CodeQL-Role
          role-session-name: codeql-session
          aws-region: us-east-1

      # Get CodeArtifact token using the assumed role
      - name: Get CodeArtifact auth token
        run: |
          export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token \
            --domain cback \
            --domain-owner 806414315277 \
            --region us-east-1 \
            --query authorizationToken \
            --output text)
          echo "CODEARTIFACT_AUTH_TOKEN=$CODEARTIFACT_AUTH_TOKEN" >> $GITHUB_ENV

      # Generate Maven settings.xml with CodeArtifact credentials
      - name: Configure Maven settings
        run: |
          mkdir -p ~/.m2
          cat > ~/.m2/settings.xml << 'EOF'
          <settings>
            <servers>
              <server>
                <id>cback-codeql-test-repo</id>
                <username>aws</username>
                <password>${env.CODEARTIFACT_AUTH_TOKEN}</password>
              </server>
            </servers>
            <profiles>
              <profile>
                <id>cback-codeql-test-repo</id>
                <activation>
                  <activeByDefault>true</activeByDefault>
                </activation>
                <repositories>
                  <repository>
                    <id>cback-codeql-test-repo</id>
                    <url>https://cback-806414315277.d.codeartifact.us-east-1.amazonaws.com/maven/codeql-test-repo/</url>
                  </repository>
                </repositories>
              </profile>
            </profiles>
          </settings>
          EOF

      # Initialize CodeQL
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v4
        with:
          languages: ${{ matrix.language }}
          queries: security-extended

      # Build with Maven (resolves shared-utils from CodeArtifact)
      - name: Build with Maven
        run: |
          cd vuln-app
          mvn compile -B -s ~/.m2/settings.xml

      # Run CodeQL analysis
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v4
        with:
          category: "/language:${{ matrix.language }}"
```

### 4.2 — Key workflow design decisions

| Decision                                              | Rationale                                                      |
| ----------------------------------------------------- | -------------------------------------------------------------- |
| `id-token: write`                                     | Required for OIDC token generation                             |
| `aws-actions/configure-aws-credentials@v4`            | Official GitHub action for OIDC → AWS STS                      |
| Maven `settings.xml` generated in-workflow            | Keeps CodeArtifact credentials ephemeral (12-hour token)       |
| `security-extended` query suite                       | Catches more vulnerability categories than default             |
| `build-mode: manual` (implied by explicit build step) | Java is a compiled language; CodeQL needs to observe the build |

---

## Phase 5: Publish Artifact & Test Pipeline

### 5.1 — Local setup & publish (one-time)

1. Configure local `~/.m2/settings.xml` per connection instructions
2. Export `CODEARTIFACT_AUTH_TOKEN`
3. Run `cd shared-utils && mvn deploy`
4. Verify artifact in CodeArtifact console

### 5.2 — Push & validate

1. Push all code to `main` branch
2. Verify GitHub Actions workflow triggers
3. Confirm OIDC authentication succeeds (check "Configure AWS credentials" step)
4. Confirm Maven resolves `shared-utils` from CodeArtifact
5. Confirm CodeQL analysis completes and detects vulnerabilities

### 5.3 — Expected CodeQL findings

| Finding                      | Source                                                | Severity |
| ---------------------------- | ----------------------------------------------------- | -------- |
| SQL Injection                | `UserController.java` → `DatabaseHelper.buildQuery()` | Critical |
| XXE                          | `App.java` → `XmlHelper.parse()`                      | High     |
| Cross-Site Scripting (XSS)   | `UserController.java` (no-op sanitizer)               | High     |
| Path Traversal               | `FileService.java`                                    | High     |
| Hardcoded Credentials        | `AuthService.java`                                    | Medium   |
| Weak Cryptographic Algorithm | `AuthService.java` (MD5)                              | Medium   |

---

## File Structure (Final)

```
oidc-codeql-test/
├── .github/
│   ├── copilot-instructions.md
│   ├── prompts/
│   │   └── initial-setup.prompt.md
│   └── workflows/
│       └── codeql.yml
├── shared-utils/                          # Phase 1: Custom Maven artifact
│   ├── pom.xml
│   └── src/main/java/com/cback/sharedutils/
│       ├── InputSanitizer.java
│       ├── XmlHelper.java
│       └── DatabaseHelper.java
├── vuln-app/                              # Phase 2: Vulnerable application
│   ├── pom.xml
│   └── src/main/java/com/cback/vulnapp/
│       ├── App.java
│       ├── UserController.java
│       ├── FileService.java
│       └── AuthService.java
├── aws/                                   # Phase 3: AWS config (reference)
│   ├── trust-policy.json
│   └── codeartifact-read-policy.json
├── PLAN.md
└── README.md
```

---

## Implementation Order & Checklist

- [ ] **Phase 1.1** — Create `shared-utils/pom.xml` with distribution management config
- [ ] **Phase 1.2** — Implement `InputSanitizer.java`, `XmlHelper.java`, `DatabaseHelper.java`
- [ ] **Phase 1.3** — Publish `shared-utils` to CodeArtifact via `mvn deploy`
- [ ] **Phase 2.1** — Create `vuln-app/pom.xml` with CodeArtifact repository & shared-utils dependency
- [ ] **Phase 2.2** — Implement `App.java`, `UserController.java`, `FileService.java`, `AuthService.java`
- [ ] **Phase 3.1** — Create IAM OIDC identity provider (if not exists)
- [ ] **Phase 3.2** — Create IAM role with trust policy scoped to this repo
- [ ] **Phase 3.3** — Attach CodeArtifact read permissions to the role
- [ ] **Phase 4.1** — Create `.github/workflows/codeql.yml`
- [ ] **Phase 5.1** — Push to GitHub, verify workflow execution
- [ ] **Phase 5.2** — Verify CodeQL findings appear in Security tab
- [ ] **Phase 5.3** — Confirm scan is incomplete without CodeArtifact access (optional validation)

---

## Risk & Mitigation

| Risk                                      | Mitigation                                                                                                                    |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| OIDC thumbprint changes                   | AWS auto-manages GitHub's OIDC thumbprint as of 2023; no manual update needed                                                 |
| CodeArtifact token expires mid-build      | Token is valid for 12 hours; builds should complete well within that                                                          |
| CodeQL cannot trace across JAR boundaries | CodeQL for Java analyzes source + bytecode; as long as the JAR is on the classpath during build, data-flow analysis will work |
| Repository trust policy too broad         | Trust policy uses `StringLike` with `repo:chetbackiewicz/oidc-codeql-test:*` — scoped to this specific repo                   |
