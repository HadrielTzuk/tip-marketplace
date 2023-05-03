def smoke(Map params) {

    echo "Running some test on ${params.kubeConfig}"
}

def regression(Map params) {

    echo "Running regression test on ${params.kubeConfig}"
}

return this
