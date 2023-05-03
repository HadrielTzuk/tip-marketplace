import groovy.json.JsonSlurperClassic

def execRequest(Map params) {

    if ( ! params.contentType ) { params.contentType = "application/json" }
    if ( ! params.reqMethod ) { params.reqMethod = "GET" }
    if ( ! params.reqUrl ) { throw "URL is not specified" }

    if ( params.debug ) { params.each { k, v -> echo "${k}: ${v}" } }

    def githubResponse
    try {
        withCredentials([string(credentialsId: 'github_personal_access_token', variable: 'SECRET')]) {
            String reqCmd = """
                            curl --silent "https://${GITHUB_HOST}/repos/${GITHUB_ORG}/${GITHUB_REPO}/${params.reqUrl}?access_token=${SECRET}" \
                            -H "Content-Type: ${params.contentType}" \
                            -X ${params.reqMethod}
                            """
            if ( params.reqData ) { reqCmd = """${reqCmd} -d "${params.reqData}" """ }
            
            if ( params.debug ) { echo "GitHub Request: ${reqCmd}" }
            
            githubResponse = sh( returnStdout: true, script: reqCmd).trim().toString()

        } // withCredentials
    } catch (err) { echo "[ERROR] ${err.toString()}" }
    if ( params.debug ) { echo "GitHub Response: ${githubResponse}" }

    return githubResponse
}

def getAllTags() {
    def resp = execRequest reqUrl: "tags", debug: false

    def jsonSlurper = new JsonSlurperClassic()
    return jsonSlurper.parseText(resp)
}

def notifyPullRequest(Map params) {

    githubNotify  account: "${GITHUB_ORG}",
                  context: params.context,
                  credentialsId: 'github_user_token',
                  description: params.desc,
                  repo: "${GITHUB_REPO}",
                  sha: "${env.GIT_COMMIT}",
                  status: params.status,
                  targetUrl: "${env.RUN_DISPLAY_URL}"
}

def mergePullRequest(String pr) {

    String resp = execRequest   reqUrl: "pulls/${pr.split('-')[1]}/merge",
                                debug: false,
                                reqMethod: "PUT",
                                reqData: """{ \\\"commit_title\\\": \\\"Merged by Jenkins\\\",
                                                \\\"commit_message\\\": \\\"Merged by Jenkins\\\",
                                                \\\"sha\\\": \\\"${env.GIT_COMMIT}\\\",
                                                \\\"merge_method\\\": \\\"squash\\\"}"""

    // String githubResponse
    // withCredentials([string(credentialsId: 'github_personal_access_token', variable: 'SECRET')]) {
    //     githubResponse = sh(
    //         returnStdout: true,
    //         script: """
    //         curl --silent "https://${GITHUB_HOST}/repos/${GITHUB_ORG}/${GITHUB_REPO}/pulls/${pr.split('-')[1]}/merge?access_token=${SECRET}" \
    //           -H "Content-Type: application/json" \
    //           -X PUT \
    //           -d "{ \\\"commit_title\\\": \\\"Merged by Jenkins\\\",
    //                 \\\"commit_message\\\": \\\"Merged by Jenkins\\\",
    //                 \\\"sha\\\": \\\"${env.GIT_COMMIT}\\\",
    //                 \\\"merge_method\\\": \\\"squash\\\"}"
    //         """).trim()

    //     echo "GitHub Response: ${githubResponse.toString()}"
    // } // withCredentials
}

def getPullRequest(String prName) {
    String resp = execRequest reqUrl: "pulls/${prName.split('-')[1]}", debug: false
    
    def jsonSlurper = new JsonSlurperClassic()
    return jsonSlurper.parseText(resp)
}

def isMergeable(String prName) {
    def pullRequest = getPullRequest(prName)

    if ( pullRequest.mergeable.equals(true) && pullRequest.rebaseable.equals(true) ) {
        if ( pullRequest.mergeable_state.equals('clean') )    {return true}
        else { echo "Pull Request is not clean" }

        if ( pullRequest.mergeable_state.equals('unstable') ) {return true}
        else { echo "Pull Request is not even unstable" }

    } else { echo "Pull Request is not mergeable or rebaseable" }
    return false
}

def getNextVersion(String branch_name) {

    def tagsList = getAllTags()

    def resp = execRequest reqUrl: "git/refs/heads/${branch_name.replace('-RC', '-PROD')}", debug: false

    def jsonSlurper = new JsonSlurperClassic()
    String recentReleaseSha = jsonSlurper.parseText(resp).object.sha.toString()

    String futureVersion = 'no_tag_found'
    tagsList.each { tag ->
        if ( tag.commit.sha.equals(recentReleaseSha) ) { 
            def x = tag.name.split('-')[0].split("\\.")
            x[1] = x[1].toInteger() + 1
            futureVersion = x.join(".")
        }
    }
    return futureVersion
}

def convertPRToBranch(Map params) {
    def pullRequest = getPullRequest(params.prBranch)

    if ( params.type.equals('source') ) {
        if ( params.sha ) { return pullRequest.head.sha } 
        else { return pullRequest.head.ref }
    } else {
        if ( params.sha ) { return pullRequest.base.sha } 
        else { return pullRequest.base.ref }
    }
}

return this
