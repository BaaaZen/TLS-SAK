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

# TLS SAK imports
from lib.connection import Connection
from lib.tls import TLS_VERSIONS
from lib.tls.tlsparameter import TLS_CipherSuite
from lib.tls.tlsparameter import TLS_CompressionMethod
from lib.tls.tlspkg import TLS_pkg
from lib.tls.tlspkg import TLS_pkg_Alert
from lib.tls.tlspkg import TLS_pkg_Handshake
from lib.tls.tlspkg import TLS_Handshake_pkg_Certificate
from lib.tls.tlspkg import TLS_Handshake_pkg_ClientHello
from lib.tls.tlspkg import TLS_Handshake_pkg_ServerHello
from lib.tls.tlspkg import TLS_Handshake_pkg_ServerHelloDone
from lib.tls.tlspkg import TLS_Handshake_pkg_ServerKeyExchange
from lib.tls.tlsexceptions import TLS_Alert_Exception
from lib.tls.tlsexceptions import TLS_Exception
from lib.tls.tlsexceptions import TLS_Parser_Exception
from lib.tls.tlsexceptions import TLS_Protocol_Exception

class TLS_Connection:
    def __init__(self, connection):
        if not issubclass(type(connection), Connection):
            raise TLS_Exception('connection has to be of type Connection for TLS connection')

        self.connection = connection
        self.buffer = b''
        self.cipher_suites = []
        self.compression_methods = []
        self.state = None

    # ---- connection property setters ----
    def setAvailableCipherSuites(self, cipher_suites):
        # validate parameter
        if type(cipher_suites) is not list:
            raise TLS_Exception('cipher_suites has to be a list of cipher suites')
        for cs in cipher_suites:
            if type(cs) is not TLS_CipherSuite:
                raise TLS_Exception('cipher_suites has to be a list of cipher suites')

        self.cipher_suites = cipher_suites

    def setAvailableCompressionMethods(self, compression_methods):
        # validate parameter
        if type(compression_methods) is not list:
            raise TLS_Exception('compression_methods has to be a list of compression methods')
        for cm in compression_methods:
            if type(cm) is not TLS_CompressionMethod:
                raise TLS_Exception('compression_methods has to be a list of compression methods')

        self.compression_methods = compression_methods

    def setClientProtocolVersion(self, protocol_version):
        # validate parameter
        if type(protocol_version) is not str:
            raise TLS_Exception('protocol_version has to be a string')
        if protocol_version not in TLS_VERSIONS:
            raise TLS_Exception('invalid protocol version in protocol_version')

        self.client_protocol_version = protocol_version


    # ---- connection property getters ----
    def getChosenCipherSuite(self):
        if hasattr(self, 'cipher_suite') and self.cipher_suite is not None:
            return self.cipher_suite
        return None

    def getChosenCompressionMethod(self):
        if hasattr(self, 'compression_method') and self.compression_method is not None:
            return self.compression_method
        return None

    def getServerProtocolVersion(self):
        if hasattr(self, 'server_protocol_version') and self.server_protocol_version is not None:
            return self.server_protocol_version
        return None

    # ---- internal methods ----
    def _readBuffer(self):
        buffer = self.connection.recv()
        self.buffer += buffer

    def _readPackage(self):
        while True:
            try:
                pkg = TLS_pkg.parser(self.buffer)
                self.buffer = self.buffer[pkg.size():]
                return pkg
            except TLS_Parser_Exception as e:
                self._readBuffer()

    # ---- state machine ----
    def connect(self):
        client_hello = TLS_Handshake_pkg_ClientHello(version=self.client_protocol_version, cipher_suites=self.cipher_suites, compression_methods=self.compression_methods)
        handshake_client_hello = TLS_pkg_Handshake(self.client_protocol_version, client_hello)
        self.connection.send(handshake_client_hello.serialize())

        serverHelloDoneReceived = False
        while not serverHelloDoneReceived:
            pkg = self._readPackage()
            if type(pkg) is TLS_pkg_Alert:
                raise TLS_Alert_Exception(pkg.getLevel(), pkg.getDescription())
            elif type(pkg) is not TLS_pkg_Handshake:
                raise TLS_Protocol_Exception('handshake package excepted, but received other package')

            # this is a handshake package
            for hs in pkg.handshake:
                if type(hs) is TLS_Handshake_pkg_ServerHello:
                    self.cipher_suite = hs.cipher_suite
                    self.compression_method = hs.compression_method
                    self.server_protocol_version = hs.version
                elif type(hs) is TLS_Handshake_pkg_ServerHelloDone:
                    serverHelloDoneReceived = True
                    break
