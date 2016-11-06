class TLS_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Exception: ' + str(self.msg)

class TLS_Malformed_Package_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Malformed_Package_Exception: ' + str(self.msg)

class TLS_Parser_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Parser_Exception: ' + str(self.msg)
