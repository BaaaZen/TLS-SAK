import binascii
import json

from lib.tls.tlsparameter import TLS_CompressionMethod

class TLS_CompressionMethod_Database():
    instance = None

    @staticmethod
    def getInstance():
        if TLS_CompressionMethod_Database.instance is None:
            TLS_CompressionMethod_Database.instance = TLS_CompressionMethod_Database()
        return TLS_CompressionMethod_Database.instance

    def __init__(self):
        self.loadDatabase()

    def loadDatabase(self):
        with open('data/compressionmethods.json') as f:
            data = f.read().replace('\n', '')

        json_data = json.loads(data)

        self.database = {}
        for ci in json_data:
            self.database[binascii.unhexlify(ci)] = json_data[ci]

    def getCompressionMethod(self, cm_id):
        if cm_id in self.database:
            return TLS_CompressionMethod(cm_id=cm_id, **self.database[cm_id])
        else:
            return TLS_CompressionMethod(cm_id=cm_id, name='unknown (' + binascii.hexlify(cm_id) + ')')

    def getAllCompressionMethods(self):
        return [self.getCompressionMethod(cm_id) for cm_id in self.database]
