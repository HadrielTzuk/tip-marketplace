def genReleaseNotes(Map params) {
    String scriptDir = 'ReleaseNotes/Generator'
    dir("${env.WORKSPACE}/${scriptDir}") {
        String outPip = sh( returnStdout: true,
            script: "DEBIAN_FRONTEND=noninteractive apt update && apt install -y python3 python3-pip && pip3 install -r ../../ops/requirements.txt")
        echo "PIP Install: ${outPip}"

        String outGen = sh( returnStdout: true,
            script: "python3 rn_creator.py --release_version ${params.releaseVersion} --minimum_version ${params.minimumVersion}")

        echo "Doc Generate: ${outGen}"
    }
}

def commitReleaseNotes() {
    sh( returnStdout: true,
        script: """
            git checkout ${branch_name}
            git add .
            git commit -m "Updated Release Notes"
            git push origin
        """)
}

return this
