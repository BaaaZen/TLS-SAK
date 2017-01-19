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

#temp
import binascii

from lib.certificate import asn1

class X509ExtensionStructureException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'X509 Structure Exception: ' + str(self.msg)


class X509Extension:
    def __init__(self, x509cert, octetstring, critical=False):
        self._x509cert = x509cert
        self._critical = critical
        self._ext = self.parse(octetstring)

    def isCritical(self):
        return self._critical

    def parse(self, octetstring):
        struct = self._struct()
        struct.parse(asn1.InputStream(octetstring))
        return struct

    def _struct(self):
        # abstract method
        pass


class X509ExtensionSubjectAltName(X509Extension):
    @staticmethod
    def getOID():
        return '2.5.29.17'

    def __init__(self, x509cert, octetstring, critical=False):
        super().__init__(x509cert, octetstring, critical)
        self._names = []
        self._extractNames()

    def _struct(self):
        return self._x509cert._struct.pSubjectAltName()

    def _extractNames(self):
        if type(self._ext) is not asn1.SequenceOf:
            raise X509ExtensionStructureException('GeneralNames structure root is ' + self._ext.__class__.__name__ + ' instead of SequenceOf')

        for generalname in self._ext:
            if type(generalname) is not asn1.Choice:
                raise X509ExtensionStructureException('GeneralName structure root is ' + generalname.__class__.__name__ + ' instead of Choice')

            if generalname.getChoiceName() in ['rfc822Name','dNSName']:
                self._names += [generalname.getChoice().getString()]
            else:
                print('not implemented choice of GeneralName: ' + generalname.getChoiceName())
                continue

    def getNames(self):
        return self._names
