pipeline {
    agent any
    environment {
        BOT_TOKEN = credentials('telegram-bot-token')
        BUILD_URL = ${env.BUILD_URL}
    }
    stages {
        stage('Build jars:') {
            steps {
                sh 'ant build'
                // Uncomment first time
                // sh 'ant make-core-deps'
            }
        }
        stage('Store artifacts') {
            steps {
                archive 'dist/connector-lib/mcf-s3output-connector.jar'
                step([$class: 'ArtifactArchiver', artifacts: 'dist/connector-lib/mcf-s3output-connector.jar', fingerprint: false])
            }
        }
    }
    post {
        failure {
            sh '''
                MESSAGE="Something is wrong with ${BUILD_URL}"
                curl --data-urlencode "text=${MESSAGE}" https://api.telegram.org/bot${BOT_TOKEN}/sendMessage?chat_id=-184042279
            '''
        }
        success {
            sh '''
                MESSAGE="Success ${BUILD_URL}"
                curl --data-urlencode "text=${MESSAGE}" https://api.telegram.org/bot${BOT_TOKEN}/sendMessage?chat_id=-184042279
            '''
        }
    }
}
