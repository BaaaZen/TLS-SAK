import binascii

from lib.tls.tlsexceptions import TLS_Exception

class TLS_CipherSuite:
    def __init__(self, cs_id):
        # validation
        if type(cs_id) is not bytes or len(cs_id) != 2:
            cs_id_str = 'None'
            if type(cs_id) is bytes:
                cs_id_str = binascii.hexlify(cs_id)
            raise TLS_Exception('invalid cipher suite id: ' + cs_id_str)

        self.cs_id = cs_id

    def serialize(self):
        return self.cs_id

class TLS_CompressionMethod:
    def __init__(self, cm_id):
        # validation
        if type(cm_id) is not bytes or len(cm_id) != 1:
            cm_id_str = 'None'
            if type(cm_id) is bytes:
                cm_id_str = binascii.hexlify(cm_id)
            raise TLS_Exception('invalid cipher suite id: ' + cm_id_str)

        self.cm_id = cm_id

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
