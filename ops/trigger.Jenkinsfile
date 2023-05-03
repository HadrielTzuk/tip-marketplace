def versionsMap = [:]
versionsMap.'12.19' = ['5.0', '5.1']
versionsMap.'12.20' = ['5.0', '5.1']
versionsMap.'12.21' = ['5.1', '5.3']


pipeline {
    agent any

    stages {
        stage('Triggering pipeline') {
            steps {
                script {
                    echo "ref: ${env.getEnvironment()}"
                    echo "map: ${versionsMap}"
                } // script
            } // steps
        } // stage
    } // stages
}
