class TLS_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Exception: ' + str(self.msg)

class TLS_Not_Implemented_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Not_Implemented_Exception: ' + str(self.msg)

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

class TLS_Protocol_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Protocol_Exception: ' + str(self.msg)

class TLS_Alert_Exception(TLS_Exception):
    def __init__(self, level, description):
        self.level = level
        self.description = description

    def __str__(self):
        return 'TLS Alert: [' + self.level + '] ' + self.description
