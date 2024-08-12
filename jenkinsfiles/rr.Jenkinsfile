import groovy.json.JsonSlurper

pipeline {
  triggers {
    cron 'H/30 * * * *'
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '500', artifactNumToKeepStr: '500'))
    disableConcurrentBuilds()
  }
  agent {
    dockerfile {
      filename 'Dockerfile'
      // This is not _actually_ running as root; Rootless docker uidmaps 0 to the
      // user that's running the rootless docker daemon. So '-u 0:0' runs as the user
      // that's mapped to the real minipc-agent Jenkins user.
      // Also, disable seccomp to ensure we can access perf counters.
      args '-u 0:0 --security-opt seccomp=unconfined --cap-drop=ALL'
    }
  }
  parameters {
    string(
      name: 'RUBY_COMMIT',
      description: 'Ruby commit to test',
      defaultValue: 'master',
    )
  }
  stages {
    stage('Prepare') {
      steps {
        sh('echo "is it possible for this to work at all?"')
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
          setCustomBuildProperty(key: 'chaos', value: "false")
          setCustomBuildProperty(key: 'asan', value: "false")
        }
      }
    }
    stage('Build ruby') {
      steps {
        dir('ruby') {
          sh '../build-ruby.rb --build'
        }
        // Uncomment to test the trace attachment handling
        // sh './make_a_test_fail.sh'
      }
    }
    stage('Run test suite (btest)') {
      steps {
        dir('ruby') {
          sh '../build-ruby.rb --btest --rr'
        }
      }
    }
    stage('Run test suite (test-tool)') {
      steps {
        dir('ruby') {
          sh '../build-ruby.rb --test-tool --rr'
        }
      }
    }
    stage('Run test suite (test-all)') {
      steps {
        dir('ruby') {
          sh '../build-ruby.rb --test-all --rr'
        }
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
