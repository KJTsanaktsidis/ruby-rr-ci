@Library('ruby-rr-ci-shared')
import au.id.kjtsanaktsidis.RubyRRCIShared
import groovy.json.JsonSlurper

def fullBuilderImage = ''

pipeline {
  agent any
  triggers {
    cron 'H/30 * * * *'
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '500', artifactNumToKeepStr: '500'))
    disableConcurrentBuilds()
  }
  parameters {
    string(
      name: 'RUBY_RR_CI_IMAGE_TAG',
      description: 'Docker image tag from https://github.com/KJTsanaktsidis/ruby-rr-ci-image to use',
      defaultValue: 'latest',
    )
    string(
      name: 'RUBY_COMMIT',
      description: 'Ruby commit to test',
      defaultValue: 'master',
    )
  }
  stages {
    stage('Prepare') {
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
        withCredentials([file(credentialsId: 'podman-auth.json', variable: 'REGISTRY_AUTH_FILE')]) {
          sh "podman pull quay.io/kjtsanaktsidis/ruby-rr-ci:${params.RUBY_RR_CI_IMAGE_TAG}"
        }

        script {
          def rubyVersion = sh(script: 'cd ruby; git rev-parse HEAD', returnStdout: true).trim()
          def imageJson = sh(
            script: "podman image inspect quay.io/kjtsanaktsidis/ruby-rr-ci:${params.RUBY_RR_CI_IMAGE_TAG}",
            returnStdout: true
          )
          def imageJsonSlurp = new JsonSlurper().parseText(imageJson)
          def imageDigest = imageJsonSlurp[0].Digest
          fullBuilderImage = "quay.io/kjtsanaktsidis/ruby-rr-ci@${imageDigest}"

          setCustomBuildProperty(key: 'image_version', value: "${fullBuilderImage}")
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
        script {
          docker.withTool('fake-docker') {
            withCredentials([file(credentialsId: 'podman-auth.json', variable: 'REGISTRY_AUTH_FILE')]) {
              docker.image(fullBuilderImage).inside {
                dir('ruby') {
                  sh '.../build-ruby.rb --build'
                }
              }
            }
          }
        }
      }
    }
    stage('Run tests') {
      steps {
        script {
          docker.withTool('fake-docker') {
            withCredentials([file(credentialsId: 'podman-auth.json', variable: 'REGISTRY_AUTH_FILE')]) {
              docker.image(fullBuilderImage).inside {
                dir('ruby') {
                  sh '.../build-ruby.rb --btest'
                }
              }
            }
          }
        }
      }
    }
  }
}
