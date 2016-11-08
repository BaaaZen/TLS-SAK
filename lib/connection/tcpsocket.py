import socket

from lib.connection import *

class Connection_TCP_Socket(Connection):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None

    def __enter__(self):
        self.connect()

    def __exit__(self, ctx_type, ctx_value, ctx_traceback):
        self.close()

    def connect(self):
        if self.socket is not None:
            raise Connection_Exception('already connected')

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
        except socket.gaierror as e:
            raise Connection_Exception(e)
        except TimeoutError as e:
            raise Connection_Exception(e)

    def close(self):
        if self.socket != None:
            self.socket.close()
            self.socket = None

    def send(self, msg):
        if self.socket is None:
            raise Connection_Exception('not connected')

        self.socket.send(msg)

    def recv(self):
        if self.socket is None:
            raise Connection_Exception('not connected')

        return self.socket.recv(4096)
