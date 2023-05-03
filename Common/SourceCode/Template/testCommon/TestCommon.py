class TestCommon(object):
    def __init__(self, number):
        self.number = number

    def test_common(self):
        res = self.number + 1
        print res
        return res