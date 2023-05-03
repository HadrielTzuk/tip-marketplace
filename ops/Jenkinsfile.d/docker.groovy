def buildAndUpload(String dockerfilePath) {

    docker.build("${DOCKER_IMAGE}:${env.VERSION}", "-f ${WORKSPACE}/${dockerfilePath} .")
}

def deleteImage() { sh "docker image rm ${DOCKER_IMAGE}:${env.VERSION}" }

return this
