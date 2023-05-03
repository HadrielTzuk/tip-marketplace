def getVersion(Map params) {
    String suffix = ""
    if ( params.timestamp ) { suffix = suffix + '-' + Long.toString(System.currentTimeMillis()) }

    def cfg = readJSON file: 'CurrentVersion.rn'
    String version = cfg['MarketplaceVersion'] + suffix
    return version
}

def getComments() {

    StringBuilder sb = new StringBuilder()

    currentBuild.changeSets.each { changeList ->
        changeList.each { change ->
           sb.append(change.comment)
        }
    }
    return sb.toString()
}

def getGitParameters() {
    echo """
        GIT_COMMIT: ${env.GIT_COMMIT}
        GIT_BRANCH: ${env.GIT_BRANCH}
        GIT_LOCAL_BRANCH: ${env.GIT_LOCAL_BRANCH}
        GIT_PREVIOUS_COMMIT: ${env.GIT_PREVIOUS_COMMIT}
        GIT_PREVIOUS_SUCCESSFUL_COMMIT: ${env.GIT_PREVIOUS_SUCCESSFUL_COMMIT}
        GIT_URL: ${env.GIT_URL}
        GIT_URL_N: ${env.GIT_URL_N}
        GIT_AUTHOR_NAME: ${env.GIT_AUTHOR_NAME}
        GIT_COMMITTER_EMAIL: ${env.GIT_COMMITTER_EMAIL}
    """
}

return this
