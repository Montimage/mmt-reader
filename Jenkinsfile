pipeline {
    agent {
        docker {
            image 'ubuntu'
            args '-u root:sudo -v $HOME/workspace/mmt-reader:/mmt-reader -v $HOME/workspace/mmt-sdk:/mmt-sdk'
        }
    }
    stages {
        stage("setup_enviroment") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'apt-get update -y'
                sh 'apt-get install -y git build-essential gcc cmake make gdb'
                sh 'apt-get install -y software-properties-common'
                sh 'apt-get install -y build-essential'
                sh 'add-apt-repository -y ppa:ubuntu-toolchain-r/test'
                sh 'apt-get update -y'
                sh 'apt-get install -y gcc-4.9 g++-4.9 cpp-4.9'
                sh 'cd /usr/bin && rm gcc g++ cpp && ln -s gcc-4.9 gcc && ln -s g++-4.9 g++ && ln -s cpp-4.9 cpp && gcc -v'
            }
        }

        stage("install_dependencies") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'apt-get install -y libpcap-dev libconfuse-dev'
            }
        }
        stage("install_dpi") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'dpkg -i /mmt-sdk/sdk/*.deb'
                sh 'ldconfig'
            }
        }

        stage("compile") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'cd /mmt-reader/ && gcc -g -o mmtReader mmtReader.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap'
                sh 'ls /mmt-reader'
            }
        }
        stage("test") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                // sh 'cd /mmt-http/ && make test'
            }
        }

        stage("create_installation") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                // sh 'cd /mmt-http/ && make deb'
            }
        }
    }
    post {
        success {
            echo 'Do something when it is successful'
            bitbucketStatusNotify(buildState: 'SUCCESSFUL')
        }
        failure {
            echo 'Do something when it is failed'
            bitbucketStatusNotify(buildState: 'FAILED')
        }
    }

}