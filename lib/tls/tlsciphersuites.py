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
import binascii
import json

# TLS SAK imports
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
            cs_id = binascii.unhexlify(ci)
            self.database[cs_id] = TLS_CipherSuite(cs_id=cs_id, **json_data[ci])

    def getCipherSuite(self, cs_id):
        if cs_id not in self.database:
            self.database[cs_id] = TLS_CipherSuite(cs_id=cs_id, name='unknown (' + binascii.hexlify(cs_id) + ')')
        return self.database[cs_id]

    def getAllCipherSuites(self):
        return [self.getCipherSuite(cs_id) for cs_id in sorted(self.database.keys())]
