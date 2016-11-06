import socket

from lib.connection import *

class Connection_TCP_Socket(Connection):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None

    def __enter__(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
        except socket.gaierror as e:
            raise Connection_Exception(e)

    def __exit__(self, ctx_type, ctx_value, ctx_traceback):
        if self.socket != None:
            self.socket.close()
            self.socket = None
