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

# temp
import binascii

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
        return b'\x60\x86\x48\x01\x65\x03\x04\x02\x01' # SHA256

class SHA1(HashAlgorithm):
    def new(self):
        return Crypto.Hash.SHA.new()

    def oid(self):
        return b'\x2b\x0e\x03\x02\x1a' # SHA1


class SignatureAlgorithm:
    def __init__(self, key):
        self._key = key

    def new(self, key):
        pass

    def padding(self, hash, l=255):
        pass

    def verify(self, hash, signature):
        key = self.new(self._key)

        # size of signature with padding
        modBits = Crypto.Util.number.size(key.n)
        modBytes = int(modBits/8)

        # generate padding -> https://tools.ietf.org/html/rfc2313#section-8.1
        lsig = b'\x00' + self.padding(hash, modBytes-1)

        # decrypt signature with public key
        (pt,) = key.encrypt(signature, 0)

        # add leading 0s
        while len(pt) < modBytes:
            pt = b'\x00' + pt

        return lsig == pt

class RSA(SignatureAlgorithm):
    def padding(self, hash, l=255):
        return b'\x01' + b'\xff'*(l-2-len(hash)) + b'\x00' + hash

    def new(self, key):
        return Crypto.PublicKey.RSA.importKey(key)
