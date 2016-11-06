from lib.connection import Connection
from lib.tls import TLS_VERSIONS
from lib.tls.tlspkg import TLS_pkg_Handshake
from lib.tls.tlspkg import TLS_Handshake_pkg_ClientHello
from lib.tls.tlspkg import TLS_Handshake_pkg_ServerHello
from lib.tls.tlspkg import TLS_Handshake_pkg_Certificate
from lib.tls.tlsexceptions import TLS_Exception

class TLS_Connection:
    def __init__(self, connection):
        self.connection = connection
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
        if has_attr(self, 'cipher_suite') and self.cipher_suite is not None:
            return self.cipher_suite
        return None

    def getChosenCompressionMethod(self):
        if has_attr(self, 'compression_method') and self.compression_method is not None:
            return self.compression_method
        return None

    def getServerProtocolVersion(self):
        if has_attr(self, 'server_protocol_version') and self.server_protocol_version is not None:
            return self.server_protocol_version
        return None


    # ---- active state machine ----
    def connect(self):
        client_hello = TLS_Handshake_pkg_ClientHello(version=self.client_protocol_version, cipher_suites=self.cipher_suites, compression_methods=self.compression_methods)
        handshake = TLS_pkg_Handshake(self.client_protocol_version, client_hello)
        print(str(handshake.serialize()))
        pass
