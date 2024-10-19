import groovy.json.JsonSlurper

pipeline {
  triggers {
    cron 'H/30 * * * *'
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '500', artifactNumToKeepStr: '500'))
    disableConcurrentBuilds()
  }
  // Explicitly specify a node, we're depending on the same podman container image being
  // available each time.
  agent any
  environment {
    PERNOSCO_USER = 'kj@kjtsanaktsidis.id.au'
    PERNOSCO_GROUP = 'github1418177'
    PERNOSCO_USER_SECRET_KEY = credentials('PERNOSCO_USER_SECRET_KEY')
  }
  parameters {
    string(
      name: 'RUBY_COMMIT',
      description: 'Ruby commit to test',
      defaultValue: 'master',
    )
  }
  stages {
    stage('Prepare SCM') {
      steps {
        dir('ruby') {
          checkout scmGit(
            userRemoteConfigs: [[
              credentialsId: 'github-pat',
              url: 'https://github.com/ruby/ruby.git',
            ]],
            branches: [[name: params.RUBY_COMMIT]],
          )
        }

        script {
          def rubyVersion = sh(script: 'cd ruby; git rev-parse HEAD', returnStdout: true).trim()
          setCustomBuildProperty(key: 'ruby_rr_ci_version', value: "${env.GIT_COMMIT}")
          setCustomBuildProperty(key: 'ruby_version', value: "${rubyVersion}")
          setCustomBuildProperty(key: 'rr', value: "true")
          setCustomBuildProperty(key: 'chaos', value: "true")
          setCustomBuildProperty(key: 'asan', value: "true")
        }
      }
    }
    stage('Build testing image') {
      steps {
        sh label: 'podman build', script: 'podman build --iidfile image.txt .'
      }
    }
    stage('Build ruby') {
      steps {
        sh label: 'make', script: '''
          podman run --rm \
            --mount type=bind,source="$(realpath .)",destination="$(realpath .)",relabel=shared \
            --workdir "$(realpath ./ruby)" \
            --security-opt unmask=/sys/fs/cgroup \
            --security-opt label=disable \
            --security-opt seccomp=unconfined \
            --cgroupns private \
            --userns=keep-id \
            --user "0:0" \
            --env "BUILD_UID=$(id -u)" \
            --env "BUILD_GID=$(id -u)" \
            --env PERNOSCO_USER \
            --env PERNOSCO_GROUP \
            --env PERNOSCO_USER_SECRET_KEY \
            "$(cat image.txt)" \
            ../build-ruby.rb --build --asan
        '''
      }
    }
    stage('Run test suite') {
      steps {
        sh label: 'make btest', script: '''
          podman run --rm \
            --mount type=bind,source="$(realpath .)",destination="$(realpath .)",relabel=shared \
            --workdir "$(realpath ./ruby)" \
            --security-opt unmask=/sys/fs/cgroup \
            --security-opt label=disable \
            --security-opt seccomp=unconfined \
            --cgroupns private \
            --userns=keep-id \
            --user "0:0" \
            --env "BUILD_UID=$(id -u)" \
            --env "BUILD_GID=$(id -u)" \
            --env PERNOSCO_USER \
            --env PERNOSCO_GROUP \
            --env PERNOSCO_USER_SECRET_KEY \
            "$(cat image.txt)" \
            ../build-ruby.rb --btest --asan --rr --pernosco --chaos
        '''
        sh label: 'make test-tool', script: '''
          podman run --rm \
            --mount type=bind,source="$(realpath .)",destination="$(realpath .)",relabel=shared \
            --workdir "$(realpath ./ruby)" \
            --security-opt unmask=/sys/fs/cgroup \
            --security-opt label=disable \
            --security-opt seccomp=unconfined \
            --cgroupns private \
            --userns=keep-id \
            --user "0:0" \
            --env "BUILD_UID=$(id -u)" \
            --env "BUILD_GID=$(id -u)" \
            --env PERNOSCO_USER \
            --env PERNOSCO_GROUP \
            --env PERNOSCO_USER_SECRET_KEY \
            "$(cat image.txt)" \
            ../build-ruby.rb --test-tool --asan --rr --pernosco --chaos
        '''
        sh label: 'make test-all', script: '''
          podman run --rm \
            --mount type=bind,source="$(realpath .)",destination="$(realpath .)",relabel=shared \
            --workdir "$(realpath ./ruby)" \
            --security-opt unmask=/sys/fs/cgroup \
            --security-opt label=disable \
            --security-opt seccomp=unconfined \
            --cgroupns private \
            --userns=keep-id \
            --user "0:0" \
            --env "BUILD_UID=$(id -u)" \
            --env "BUILD_GID=$(id -u)" \
            --env PERNOSCO_USER \
            --env PERNOSCO_GROUP \
            --env PERNOSCO_USER_SECRET_KEY \
            "$(cat image.txt)" \
            ../build-ruby.rb --test-all --asan --rr --pernosco --chaos
        '''
      }
    }
  }
  post {
    always {
      junit(
       testResults: 'ruby/build/test_output_dir/**/junit.xml',
       testDataPublishers: [[$class:'AttachmentPublisher']],
       keepLongStdio: true,
       allowEmptyResults: true
      )
    }
  }
}
