import binascii
import json

from lib.tls.tlsparameter import TLS_CipherSuite

class TLS_CipherSuite_Database():
    instance = None

    @staticmethod
    def getInstance():
        if TLS_CipherSuite_Database.instance is None:
            TLS_CipherSuite_Database.instance = TLS_CipherSuite_Database()
        return TLS_CipherSuite_Database.instance

    def __init__(self):
        self.loadDatabase()

    def loadDatabase(self):
        with open('data/ciphersuites.json') as f:
            data = f.read().replace('\n', '')

        json_data = json.loads(data)

        self.database = {}
        for ci in json_data:
            self.database[binascii.unhexlify(ci)] = json_data[ci]

    def getCipherSuite(self, cs_id):
        if cs_id in self.database:
            return TLS_CipherSuite(cs_id=cs_id, **self.database[cs_id])
        else:
            return TLS_CipherSuite(cs_id=cs_id, name='unknown (' + binascii.hexlify(cs_id) + ')')

    def getAllCipherSuites(self):
        return [self.getCipherSuite(cs_id) for cs_id in self.database]
