// Thin wrapper: all logic is in ci/run.sh. Code of a change request is not trusted with the Docker socket or with
// credentials: it runs ci/run.sh unit, offline, in a container without the socket. The full verify (tests start
// containers) runs only for the main branch, on the dedicated agent labelled docker-dedicated.
pipeline {
    agent none
    stages {
        stage('unit (change request)') {
            when { changeRequest() }
            agent {
                docker {
                    image 'maven:3.9.12-eclipse-temurin-25'
                }
            }
            environment {
                MCP_MAVEN_OFFLINE = 'true'
            }
            steps {
                sh 'ci/run.sh unit'
            }
            post {
                always {
                    junit 'target/surefire-reports/TEST-*.xml'
                }
            }
        }
        stage('verify (main)') {
            when { branch 'main' }
            agent {
                docker {
                    label 'docker-dedicated'
                    image 'maven:3.9.12-eclipse-temurin-25'
                    args '-v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                sh 'ci/run.sh verify'
            }
            post {
                always {
                    junit 'target/surefire-reports/TEST-*.xml'
                }
            }
        }
    }
}
