// Thin wrapper: all logic is in ci/run.sh. The agent needs the Docker socket (the tests start containers) and the
// credentials MCP_MAVEN_REPOSITORY_URL, MCP_MAVEN_REPOSITORY_USER, MCP_MAVEN_REPOSITORY_PASSWORD for the mcp-contracts artifacts.
pipeline {
    agent {
        docker {
            image 'maven:3.9.12-eclipse-temurin-25'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }
    stages {
        stage('verify') {
            steps {
                sh 'ci/run.sh verify'
            }
        }
    }
    post {
        always {
            junit 'target/surefire-reports/TEST-*.xml'
        }
    }
}
