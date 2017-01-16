# TLS-SAK - TLS Swiss Army Knife
# https://github.com/RBT-itsec/TLS-SAK
# Copyright (C) 2017 by Mirko Hansen / ARGE Rundfunk-Betriebstechnik
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

import Crypto
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from lib.certificate import asn1

class HashAlgorithm:
    def new(self):
        pass

    def oid(self):
        pass

    def hash(self, msg):
        m = self.new()
        m.update(msg)
        return m.digest()

    def toBER(self, msg):
        hashValue = asn1.OctetString()
        hashValue.setRawContent(self.hash(msg))

        root = asn1.Sequence()
        root.addItem(self._algorithmIdentifier())
        root.addItem(hashValue)

        return root.toBER()

    def _algorithmIdentifier(self):
        oid = asn1.ObjectIdentifier()
        # TODO: use oid parser
        oid.setRawContent(self.oid())

        ai = asn1.Sequence()
        ai.addItem(oid)
        ai.addItem(asn1.Null())

        return ai


class SHA256(HashAlgorithm):
    def new(self):
        return Crypto.Hash.SHA256.new()

    def oid(self):
        return b'\x60\x86\x48\x01\x65\x03\x04\x02\x01'

class SHA1(HashAlgorithm):
    def new(self):
        return Crypto.Hash.SHA.new()

    def oid(self):
        return b'\x2b\x0e\x03\x02\x1a'


class SignatureAlgorithm:
    def __init__(self, key):
        self._key = key

    def new(self, key):
        pass

    def verify(self, hash, signature):
        # hash = int.from_bytes(hash.digest(), byteorder='big')
        # signature = int.from_bytes(signature, byteorder='big')
        key = self.new(self._key)
        #verifier = PKCS1_v1_5.new(self.new(self._key))
        return key.verify(hash, signature)

class RSA(SignatureAlgorithm):
    def new(self, key):
        return Crypto.PublicKey.RSA.importKey(key)
