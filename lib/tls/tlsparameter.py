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

# TLS SAK imports
from lib.tls.tlsexceptions import TLS_Exception
from lib.tls.tlsratings import TLS_Rating
from lib.tls.tlsratings import TLS_Ratings_Database

class TLS_CipherSuite:
    def __init__(self, cs_id, name='unknown', kx=None, au=None, enc=None, bits=None, mac=None, ref=None):
        # validation
        if type(cs_id) is not bytes or len(cs_id) != 2:
            cs_id_str = 'None'
            if type(cs_id) is bytes:
                cs_id_str = str(binascii.hexlify(cs_id))
            raise TLS_Exception('invalid cipher suite id: ' + cs_id_str)

        self.cs_id = cs_id
        self.name = name
        self.kx = kx
        self.au = au
        self.enc = enc
        self.bits = bits
        self.mac = mac
        self.ref = ref

    def serialize(self):
        return self.cs_id

    def getRating(self, protocol):
        ra = {}
        ra['protocol'] = TLS_Ratings_Database.getInstance().getRating(param='protocol', setting=protocol)
        ra['kx'] = TLS_Ratings_Database.getInstance().getRating(param='kx', setting=self.kx)
        ra['au'] = TLS_Ratings_Database.getInstance().getRating(param='au', setting=self.au)
        ra['enc'] = TLS_Ratings_Database.getInstance().getRating(param='enc', setting=self.enc)
        ra['bits'] = TLS_Ratings_Database.getInstance().getRating(param='bits', setting=self.bits)
        ra['mac'] = TLS_Ratings_Database.getInstance().getRating(param='mac', setting=self.mac)
        return TLS_Rating.getParentRating(ra)

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
