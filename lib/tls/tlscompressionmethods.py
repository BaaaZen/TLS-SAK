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
