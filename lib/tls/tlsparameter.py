import binascii

from lib.tls.tlsexceptions import TLS_Exception

class TLS_CipherSuite:
    def __init__(self, cs_id, name='unknown', protocol=None, kx=None, au=None, enc=None, bits=None, mac=None, ref=None):
        # validation
        if type(cs_id) is not bytes or len(cs_id) != 2:
            cs_id_str = 'None'
            if type(cs_id) is bytes:
                cs_id_str = str(binascii.hexlify(cs_id))
            raise TLS_Exception('invalid cipher suite id: ' + cs_id_str)

        self.cs_id = cs_id
        self.name = name
        self.protocol = protocol
        self.kx = kx
        self.au = au
        self.enc = enc
        self.bits = bits
        self.mac = mac
        self.ref = ref

    def serialize(self):
        return self.cs_id

class TLS_CompressionMethod:
    def __init__(self, cm_id, name='unknown'):
        # validation
        if type(cm_id) is not bytes or len(cm_id) != 1:
            cm_id_str = 'None'
            if type(cm_id) is bytes:
                cm_id_str = str(binascii.hexlify(cm_id))
            raise TLS_Exception('invalid compression method id: ' + cm_id_str)

        self.cm_id = cm_id
        self.name = name

    def serialize(self):
        return self.cm_id


class TLS_Extension:
    def __init__(self):
        pass

    def serialize(self):
        pass


class TLS_Certificate:
    def __init__(self):
        pass

    def serialize(self):
        pass

    def parse(self, buffer):
        pass
