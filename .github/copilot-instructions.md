This repository is going to be used to test GitHub's Advanced CodeQL security scan.  The repository will need reach out to AWS CodeArtifact to get Maven Artifact. 

The First step we'll need to do is create a plan for implementation. I've already created a Maven codeartifact repository, with connection instructions below:

Connection Instruction.
0. OS: Mac & Linux
1. Package Manager: mvn
2a Select a config method: push to your repository
  2a.1. Add this distribution management config to your pom.xml
  <distributionManagement>
  <repository>
    <id>cback-codeql-test-repo</id>
    <name>cback-codeql-test-repo</name>
    <url>https://cback-806414315277.d.codeartifact.us-east-1.amazonaws.com/maven/codeql-test-repo/</url>
  </repository>
</distributionManagement>
2b. Select a config method: push to your repository
  2b.1. Add this distribution management config to your pom.xml:
  Step 3: Export a CodeArtifact authorization token for authorization to your repository from your preferred shell.
The token expires in 12 hours.
export CODEARTIFACT_AUTH_TOKEN=`aws codeartifact get-authorization-token --domain cback --domain-owner 806414315277 --region us-east-1 --query authorizationToken --output text`
Copy
Step 4: Add your server to the list of servers to your settings.xml.
settings.xml is typically found at ~/.m2/settings.xml. Adding the below snippet section allows Maven to pass the CODEARTIFACT_AUTH_TOKEN environment variable as a token in HTTP requests.
<servers>
  <server>
    <id>cback-codeql-test-repo</id>
    <username>aws</username>
    <password>${env.CODEARTIFACT_AUTH_TOKEN}</password>
  </server>
</servers>
Copy
Step 5: Add a profile containing your repository to your settings.xml.
You can use any value in the <id> element, but it must be the same in both the <server> element from Step 4 and the <repository> elements. This enables the specified credentials to be included in requests to CodeArtifact.
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
Copy
Step 6: (Optional) Set a mirror in your settings.xml that captures all connections and routes them to your repository instead of a public repository.
<mirrors>
  <mirror>
    <id>cback-codeql-test-repo</id>
    <name>cback-codeql-test-repo</name>
    <url>https://cback-806414315277.d.codeartifact.us-east-1.amazonaws.com/maven/codeql-test-repo/</url>
    <mirrorOf>*</mirrorOf>
  </mirror>
</mirrors>


We'll need to create an artifact in the repository to retrieve, and ensure that the code scan would be incomplete without the code within the registry. 
Next, we'll need a purposefully vulnerable application, that code will be scanned, and vulnerabilities will be identified by CodeQL. 
Next, we'll need to setup as the auth mechanism within our advanced CodeQL configuration file, such that the code is retrieved using that mechanism.  Documentation around OIDC with AWS and GitHub can be found here.
https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws

Begin generating a plan for this application. 