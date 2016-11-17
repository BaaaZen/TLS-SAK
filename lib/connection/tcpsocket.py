# TLS-SAK - TLS Swiss Army Knife
# https://github.com/RBT-itsec/TLS-SAK
# Copyright (C) 2016 by Mirko Hansen / ARGE Rundfunk-Betriebstechnik
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# generic imports
import socket

# TLS SAK imports
from lib.connection import Connection
from lib.connection import Connection_Exception

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
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
        except socket.gaierror as e:
            raise Connection_Exception(e)
        except socket.timeout as e:
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

        data = self.socket.recv(4096)
        if data is None or len(data) < 1:
            raise Connection_Exception('no data received from socket')
        return data
