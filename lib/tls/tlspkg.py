import struct
import time

from lib.tls import TLS_VERSIONS
from lib.tls.tlsexceptions import TLS_Exception, TLS_Malformed_Package_Exception, TLS_Parser_Exception
from lib.tls.tlsparameter import TLS_CipherSuite, TLS_CompressionMethod, TLS_Extension

class TLS_pkg():
    def __init__(self):
        self.parseSize = None

    def serialize(self):
        pass

    def parse(self, buffer):
        pass

    def size(self):
        if self.parseSize is not None:
            return self.parseSize
        else:
            return len(self.serialize())

    @staticmethod
    def parser_assert_len(buffer, length):
        if type(buffer) is not bytes:
            raise TLS_Exception('invalid type of buffer for parser: bytes required!')
        if len(buffer) < length:
            raise TLS_Parser_Exception('buffer too short: ' + len(buffer) + ' < ' + length)

    @staticmethod
    def parse(buffer):
        TLS_pkg.parser_assert_len(buffer, 1)
        if buffer[0:1] == TLS_pkg_Handshake.PACKAGETYPE:
            return TLS_pkg_Handshake().parse(buffer)
        else:
            raise TLS_Exception('unknown TLS package type: ' + binascii.hexlify(buffer[0:1]))


class TLS_pkg_Handshake(TLS_pkg):
    PACKAGETYPE = b'\x16'

    def __init__(self, version='TLSv1', handshake=None):
        self.version = version
        self.handshake = handshake

    def serialize(self):
        if self.handshake is None or not issubclass(type(self.handshake), TLS_Handshake_pkg):
            raise TLS_Exception('missing handshake content in handshake package')
        if self.version not in TLS_VERSIONS:
            raise TLS_Exception('invalid version of handshake for handshake package')

        hs_content = self.handshake.serialize()
        hs_size = struct.pack('!H', len(hs_content))

        #  1 byte   package type        (0x16 = Handshake)
        #  2 bytes  SSL/TLS version     (0x0301 = SSL 3.1 = TLS 1.0)
        #  2 bytes  size in bytes of handshake package
        # .. bytes  content of handshake package

        return self.PACKAGETYPE + TLS_VERSIONS[self.version] + hs_size + hs_content

    def parse(self, buffer):
        self.parser_assert_len(buffer, 5)

        # get version
        version = buffer[1:3]
        self.version = 'unknown (' + binascii.hexlify(version) + ')'
        for v in TLS_VERSIONS:
            if TLS_VERSIONS[v] == version:
                self.version = v
                break

        # size of content
        hs_size = struct.unpack('!H', buffer[3:5])
        self.parser_assert_len(buffer, 5 + hs_size)

        # valid size of content?
        if hs_size < 1:
            self.handshake = None
            return

        # fetch and parse content
        hs_content = buffer[5:5+hs_size]
        if hs_content[0:1] == TLS_pkg_Handshake_ClientHello.PACKAGETYPE:
            self.handshake = TLS_pkg_Handshake_ClientHello()
        elif hs_content[0:1] == TLS_pkg_Handshake_ServerHello.PACKAGETYPE:
            self.handshake = TLS_pkg_Handshake_ServerHello()
        elif hs_content[0:1] == TLS_pkg_Handshake_Certificate.PACKAGETYPE:
            self.handshake = TLS_pkg_Handshake_Certificate()
        else:
            raise TLS_Exception('unknown TLS handshake package type: ' + binascii.hexlify(hs_content[0:1]))

        self.handshake.parse(hs_content)


class TLS_Handshake_pkg(TLS_pkg):
    pass

class TLS_Handshake_pkg_ClientHello(TLS_Handshake_pkg):
    PACKAGETYPE = b'\x01'
    def __init__(self, version='TLSv1', timestamp=int(time.time()), random=b'\x00'*28, session_id=None, cipher_suites=None, compression_methods=None, extensions=None):
        # validate content
        if session_id is None:
            session_id = b''

        self.version = version
        self.timestamp = timestamp
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = compression_methods
        self.extensions = extensions

    def serialize(self):
        if self.version not in TLS_VERSIONS:
            raise TLS_Exception('invalid version of protocol in client hello package')
        if type(self.timestamp) is not int:
            raise TLS_Exception('invalid timestamp type in client hello package')
        if len(self.random) != 28:
            raise TLS_Exception('invalid length of random number in client hello package')
        #TODO: validity check of session_id
        if type(self.cipher_suites) is not list or len(self.cipher_suites) < 1:
            raise TLS_Exception('missing list of cipher suites in client hello package')
        for cs in self.cipher_suites:
            if type(cs) is not TLS_CipherSuite:
                raise TLS_Exception('invalid item in cipher suites in client hello package: ' + type(cs))
        if type(self.compression_methods) is not list:
            self.compression_methods = []
        for cm in self.compression_methods:
            if type(cm) is not TLS_CompressionMethod:
                raise TLS_Exception('invalid item in compression methods in client hello package: ' + type(cm))
        if type(self.extensions) is not list:
            self.extensions = []
        for ext in self.extensions:
            if type(ext) is not TLS_Extension:
                raise TLS_Exception('invalid item in extensions in client hello package: ' + type(ext))

        v = TLS_VERSIONS[self.version]
        ts = struct.pack('!I', self.timestamp)
        rand = self.random
        sid_content = self.session_id
        sid_size = struct.pack('!B', len(sid_content))
        cs_content = b''.join(cs.serialize() for cs in self.cipher_suites)
        cs_size = struct.pack('!H', len(cs_content))
        cm_content = b''.join(cm.serialize() for cm in self.compression_methods)
        cm_len = struct.pack('!B', len(cm_content))
        ext_content = b''.join(ext.serialize() for ext in self.extensions)
        ext_size = struct.pack('!H', len(ext_content))

        #  1 byte   handshake type      (0x01 = ClientHello)
        #  3 bytes  size in bytes of ClientHello package
        #  2 bytes  SSL/TLS version     (0x0303 = TLS 1.2)
        #  4 bytes  UNIX Timestamp
        # 28 bytes  random bytes
        #  1 byte   session id length   (0x00 = no session id)
        # .. bytes  content of session id
        #  2 bytes  size in bytes of cipher suites
        #  2 bytes*x  cipher suite id   (0xc02b = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        #  1 byte   number of compression methods
        #  1 byte*x   compression method id     (0x00 = No compression)
        #  2 bytes  size in bytes of extensions
        # .. bytes  extensions

        pkg_content = v + ts + rand + sid_size + sid_content + cs_size + cs_content + cm_len + cm_content + ext_size + ext_content
        pkg_size = struct.pack('!I', len(pkg_content))[-3:]

        return self.PACKAGETYPE + pkg_size + pkg_content

    def parse(self, buffer):
        self.parser_assert_len(buffer, 4)

        # additional size for dynamic fields
        add_size = 0

        # fetch size of ClientHello package
        pkg_size = struct.unpack('!I', b'\x00' + buffer[1:4])
        self.parser_assert_len(buffer, 4 + pkg_size)
        pkg_content = buffer[4:4+pkg_size]

        # pkg_size valid?
        if pkg_size < 38:
            raise TLS_Malformed_Package_Exception('size of ClientHello package content smaller than minimum for a valid package: ' + pkg_size)

        # fetch SSL/TLS version
        version = pkg_content[0:2]
        self.version = 'unknown (' + binascii.hexlify(version) + ')'
        for v in TLS_VERSIONS:
            if TLS_VERSIONS[v] == version:
                self.version = v
                break

        # fetch timestamp and random
        self.timestamp = struct.unpack('!I', pkg_content[2:6])
        self.random = pkg_content[6:34]

        # fetch session id size
        sid_size = struct.unpack('!B', pkg_content[34:35])
        add_size += sid_size

        # pkg_size valid?
        if pkg_size < 38 + add_size:
            raise TLS_Malformed_Package_Exception('size of ClientHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(38 + add_size))

        # fetch session id
        self.session_id = pkg_content[35:35+sid_size]

        # fetch size of cipher suites
        cs_size = struct.unpack('!H', pkg_content[35+sid_size:35+sid_size+2])
        add_size += cs_size

        # validate cipher suite size
        if cs_size % 2 != 0:
            raise TLS_Malformed_Package_Exception('invalid size of cipher suite list: must be an even size!')

        # pkg_size valid?
        if pkg_size < 38 + add_size:
            raise TLS_Malformed_Package_Exception('size of ClientHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(38 + add_size))

        # fetch all cipher suites
        self.cipher_suites = []
        for i in range(0, cs_size, 2):
            self.cipher_suites += [TLS_CipherSuite(pkg_content[35+sid_size+2+i:35+sid_size+2+i+2])]

        # fetch size of compression methods
        cm_size = struct.unpack('!B', pkg_content[35+sid_size+2+cs_size:35+sid_size+2+cs_size+1])
        add_size += cm_size

        # pkg_size valid?
        if pkg_size < 38 + add_size:
            raise TLS_Malformed_Package_Exception('size of ClientHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(38 + add_size))

        # fetch all compression methods
        self.compression_methods = []
        for i in range(0, cm_size):
            self.compression_methods += [TLS_CompressionMethod(pkg_content[35+sid_size+2+cs_size+1+i:35+sid_size+2+cs_size+1+i+1])]

        # (optional) fetch size of extensions
        self.extensions = []
        if pkg_size < 38 + add_size + 2:
            return

        ext_size = struct.unpack('!H', pkg_content[35+sid_size+2+cs_size+1+cm_size:35+sid_size+2+cs_size+1+cm_size+2])
        add_size += ext_size

        # pkg_size valid?
        if pkg_size < 40 + add_size:
            raise TLS_Malformed_Package_Exception('size of ClientHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(40 + add_size))

        # TODO: fetch extensions


class TLS_Handshake_pkg_ServerHello(TLS_Handshake_pkg):
    PACKAGETYPE = b'\x02'
    def __init__(self, version='TLSv1', timestamp=int(time.time()), random=b'\x00'*28, session_id=None, cipher_suite=None, compression_method=None, extensions=None):
        # validate content
        if session_id is None:
            session_id = b''

        self.version = version
        self.timestamp = timestamp
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.compression_method = compression_method
        self.extensions = extensions

    def serialize(self):
        if self.version not in TLS_VERSIONS:
            raise TLS_Exception('invalid version of protocol in server hello package')
        if type(self.timestamp) is not int:
            raise TLS_Exception('invalid timestamp type in server hello package')
        if len(self.random) != 28:
            raise TLS_Exception('invalid length of random number in server hello package')
        #TODO: validity check of session_id
        if type(self.cipher_suite) is not TLS_CipherSuite:
            raise TLS_Exception('invalid cipher suite in server hello package: ' + type(self.cipher_suite))
        if type(self.compression_method) is not TLS_CipherSuite:
            raise TLS_Exception('invalid compression method in server hello package')
        if type(self.extensions) is not list:
            self.extensions = []
        for ext in self.extensions:
            if type(ext) is not TLS_Extension:
                raise TLS_Exception('invalid item in extensions in server hello package: ' + type(ext))

        v = TLS_VERSIONS[self.version]
        ts = struct.pack('!I', self.timestamp)
        rand = self.random
        sid_content = self.session_id
        sid_size = struct.pack('!B', len(sid_content))
        cs_content = self.cipher_suite.serialize()
        cm_content = self.compression_methods.serialize()
        ext_content = b''.join(ext.serialize() for ext in self.extensions)
        ext_size = struct.pack('!H', len(ext_content))

        #  1 byte   handshake type      (0x01 = ClientHello)
        #  3 bytes  size in bytes of ClientHello package
        #  2 bytes  SSL/TLS version     (0x0303 = TLS 1.2)
        #  4 bytes  UNIX Timestamp
        # 28 bytes  random bytes
        #  1 byte   session id length   (0x00 = no session id)
        # .. bytes  content of session id
        #  2 bytes  cipher suite id
        #  1 byte   compression method id     (0x00 = No compression)
        #  2 bytes  size in bytes of extensions
        # .. bytes  extensions

        pkg_content = v + ts + rand + sid_size + sid_content + cs_content + cm_content + ext_size + ext_content
        pkg_size = struct.pack('!I', len(pkg_content))[-3:]

        return self.PACKAGETYPE + pkg_size + pkg_content

    def parse(self, buffer):
        self.parser_assert_len(buffer, 4)

        # additional size for dynamic fields
        add_size = 0

        # fetch size of ServerHello package
        pkg_size = struct.unpack('!I', b'\x00' + buffer[1:4])
        self.parser_assert_len(buffer, 4 + pkg_size)
        pkg_content = buffer[4:4+pkg_size]

        # pkg_size valid?
        if pkg_size < 38:
            raise TLS_Malformed_Package_Exception('size of ServerHello package content smaller than minimum for a valid package: ' + pkg_size)

        # fetch SSL/TLS version
        version = pkg_content[0:2]
        self.version = 'unknown (' + binascii.hexlify(version) + ')'
        for v in TLS_VERSIONS:
            if TLS_VERSIONS[v] == version:
                self.version = v
                break

        # fetch timestamp and random
        self.timestamp = struct.unpack('!I', pkg_content[2:6])
        self.random = pkg_content[6:34]

        # fetch session id size
        sid_size = struct.unpack('!B', pkg_content[34:35])
        add_size += sid_size

        # pkg_size valid?
        if pkg_size < 38 + add_size:
            raise TLS_Malformed_Package_Exception('size of ServerHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(38 + add_size))

        # fetch session id
        self.session_id = pkg_content[35:35+sid_size]

        # fetch cipher suite
        self.cipher_suite = TLS_CipherSuite(pkg_content[35+sid_size:35+sid_size+2])

        # fetch compression method
        self.compression_method = TLS_CompressionMethod(pkg_content[35+sid_size+2:35+sid_size+3])

        # (optional) fetch size of extensions
        self.extensions = []
        if pkg_size < 38 + add_size + 2:
            return

        ext_size = struct.unpack('!H', pkg_content[35+sid_size+3:35+sid_size+5])
        add_size += ext_size

        # pkg_size valid?
        if pkg_size < 40 + add_size:
            raise TLS_Malformed_Package_Exception('size of ServerHello package content smaller than minimum for a valid package: ' + pkg_size + ' instead of ' + str(40 + add_size))

        # TODO: fetch extensions

class TLS_Handshake_pkg_Certificate(TLS_Handshake_pkg):
    PACKAGETYPE = b'\x0b'
    def __init__(self, certificates=None):
        self.certificates = certificates

    def serialize(self):
        if type(self.certificates) is not list or len(self.certificates) < 1:
            raise TLS_Exception('missing certificate for certificate package')
        for crt in self.certificates:
            if type(crt) is not TLS_Certificate:
                raise TLS_Exception('invalid item in certificate list in certificate package: ' + type(crt))

        #  1 byte   handshake type      (0x0b = Certificate)
        #  3 bytes  size in bytes of Certificate package
        # .. bytes  content of list of certificates

        # - list of certificates -
        #  3 bytes  size in bytes of certificate
        # .. bytes  content of certificate

        # create list of certificates
        certs_content = b''
        for crt in self.certificates:
            crt_content = crt.serialize()
            crt_size = struct.pack('!I', len(crt_content))[-3:]
            certs_content += crt_size + crt_content

        certs_size = struct.pack('!I', len(certs_content))[-3:]

        return self.PACKAGETYPE + certs_size + certs_content

    def parse(self, buffer):
        self.parser_assert_len(buffer, 4)

        # fetch size of Certificate package
        pkg_size = struct.unpack('!I', b'\x00' + buffer[1:4])
        self.parser_assert_len(buffer, 4 + pkg_size)
        pkg_content = buffer[4:4+pkg_size]

        # pointer for current position in pkg_content
        pos = 0
        self.certificates = []

        # extract all certificates
        while pos < pkg_size:
            if pos + 3 >= pkg_size:
                raise TLS_Parser_Exception('invalid size of certificate list in certificate package')

            # size of next certificate
            crt_size = struct.unpack('!I', b'\x00' + pkg_content[pos:pos+3])
            if pos + 3 + crt_size > pkg_size:
                raise TLS_Parser_Exception('invalid size descriptor for certificate list in certificate package')

            # content of certificate
            self.certificates += [TLS_Certificate().parse(pkg_content[pos+3:pos+3+crt_size])]

            # increase pointer
            pos += 3 + crt_size
