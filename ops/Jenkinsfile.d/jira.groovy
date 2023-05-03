import groovy.json.JsonSlurperClassic

def execRequest(Map params) {

    if ( ! params.contentType ) { params.contentType = "application/json" }
    if ( ! params.reqMethod ) { params.reqMethod = "GET" }
    if ( ! params.apiVersion ) { params.apiVersion = "2" }
    if ( ! params.reqUrl ) { throw "URL is not specified" }

    if ( params.debug ) { params.each { k, v -> echo "${k}: ${v}" } }

    String jiraResponse
    try {
        withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'jira_http',
                      usernameVariable: 'USERNAME', passwordVariable: 'TOKEN']]) {

            String reqCmd = """
                            curl --silent "https://${JIRA_HOST}/rest/api/${params.apiVersion}/${params.reqUrl}" \
                            -H "Content-Type: ${params.contentType}" \
                            -u ${USERNAME}:${TOKEN} \
                            -X ${params.reqMethod}
                            """
            if ( params.reqData ) { reqCmd = """${reqCmd} -d "${params.reqData}" """ }
            
            if ( params.debug ) { echo "Jira Request: ${reqCmd}" }
            
            jiraResponse = sh( returnStdout: true, script: reqCmd).trim().toString()

        } // withCredentials
    } catch (err) { echo "[ERROR] ${err.toString()}" }
    if ( params.debug ) { echo "Jira Response: ${jiraResponse}" }

    return jiraResponse
}

def getTransitionId(String statusName, String isssueId) {

    def resp = execRequest reqUrl: "issue/${isssueId}/transitions", debug: false

    def jsonSlurper = new JsonSlurperClassic()
    String code
    jsonSlurper.parseText(resp).transitions.each {
        if ( it.name.equals(statusName) ) {
            println("IT: ${it.toString()}")
            code = it.id
        }
    }
    return code
}

def updateStatus(Map params) {

    def statusId = getTransitionId(params.toStatus, params.issueId)

    // String data = "{ \"transition\": { \"id\": \"${statusId}\" } }"

    def resp = execRequest reqUrl: "issue/${params.issueId}", reqMethod: "PUT", debug: false
    
    def jsonSlurper = new JsonSlurperClassic()
    return jsonSlurper.parseText(resp)
}

def findIssueByBranch(String branch) {

    String originBranch = branch
    if ( branch =~ /^(PR-[0-9]*)/ ) {
        def github = load 'ops/Jenkinsfile.d/github.groovy'
        originBranch = github.convertPRToBranch prBranch: branch, type: 'source', sha: false
    }

    def matcher = ( originBranch =~ /^(TIPG-[0-9]*)/ )
    String issueId = matcher[0][0]
    return issueId
}

def isPlannedForNextVersion(Map params) {

    def resp = execRequest reqUrl: "issue/${params.issueId}", debug: false

    def jsonSlurper = new JsonSlurperClassic()
    Boolean permitted = false
    try {
        jsonSlurper.parseText(resp).fields.fixVersions.each { fv ->
            if ( fv.name.equals(params.nextVersion) ) { permitted = true }
        }
    } catch (err) { echo "[ERROR] ${err.toString()}" }

    return permitted
}

return this
