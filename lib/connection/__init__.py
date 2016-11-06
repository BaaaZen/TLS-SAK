class Connection:
    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, ctx_type, ctx_value, ctx_traceback):
        pass

class Connection_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Connection Exception: ' + str(self.msg)
