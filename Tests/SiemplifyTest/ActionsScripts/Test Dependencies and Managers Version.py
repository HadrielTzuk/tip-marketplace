from TestManager1 import TestManager1
from TestManager2 import TestManager2
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
import pyjokes
import cowsay
import subprocess


@output_handler
def main():
    siemplify = SiemplifyAction()

    t1 = TestManager1()
    assert t1.get_version() == "A1"

    t2 = TestManager2()
    assert t2.get_version() == "A2"

    cowsay.cheese("YAY")
    print pyjokes.get_joke()

    assert pyjokes.__version__ == "0.5.0"
    proc = subprocess.Popen("pip freeze", stdout=subprocess.PIPE, shell=True)
    out, err = proc.communicate()
    assert "cowsay==2.0.3" in out

    siemplify.end("Success!", 'true')


if __name__ == '__main__':
    main()
