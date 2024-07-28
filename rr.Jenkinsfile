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
        sh 'bash make_a_test_fail.sh'
      }
    }
    stage('Run tests') {
      steps {
        dir('ruby') {
          sh '../build-ruby.rb --btest --rr'
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
