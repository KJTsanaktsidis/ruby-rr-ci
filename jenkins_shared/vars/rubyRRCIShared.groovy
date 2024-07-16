def latestVersion() {
  Jenkins.instance.getItemByFullName('ruby-rr-ci Tester Image/main')
                  .getLastSuccessfulBuild()
                  .getAction(hudson.plugins.git.util.BuildData.class)
                  .lastBuiltRevision.sha1String
}

