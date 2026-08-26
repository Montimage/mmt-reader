pipeline {
    agent {
        docker {
            image 'ubuntu:24.04'
            args '-u root:sudo -v $HOME/workspace/mmt-reader:/mmt-reader -v $HOME/workspace/mmt-sdk:/mmt-sdk'
        }
    }
    stages {
        stage("setup_enviroment") {
            steps {
                sh 'apt-get update -y'
                sh 'apt-get install -y git build-essential gcc cmake make gdb jq'
                sh 'gcc --version'
            }
        }

        stage("install_dependencies") {
            steps {
                sh 'apt-get install -y libpcap-dev'
            }
        }
        stage("install_dpi") {
            steps {
                sh 'dpkg -i /mmt-sdk/sdk/*.deb'
                sh 'ldconfig'
            }
        }

        stage("compile") {
            steps {
                sh 'cd /mmt-reader/ && make'
                sh 'ls /mmt-reader'
            }
        }
        stage("test") {
            steps {
                sh 'cd /mmt-reader/ && make test'
            }
        }

        stage("create_installation") {
            steps {
                // sh 'cd /mmt-http/ && make deb'
            }
        }
    }
    post {
        success {
            echo 'Do something when it is successful'
        }
        failure {
            echo 'Do something when it is failed'
        }
    }

}
