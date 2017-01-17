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

import base64
import hashlib
import os
import os.path

from lib.certificate import asn1
from lib.certificate import x509certificate

class CertificateStore:
    @staticmethod
    def parseCertificateFromFile(filename):
        certheader = b'-----BEGIN CERTIFICATE-----\n'
        certfooter = b'\n-----END CERTIFICATE-----\n'
        with open(filename, 'rb') as f:
            content = f.read()
        if content[:len(certheader)] == certheader and content[-len(certfooter):] == certfooter:
            # this file is in PEM format
            # remove header and footer
            content = content[len(certheader):-len(certfooter)]
            # remove newlines
            content = ''.join(content.decode('utf-8').split('\n')).encode('utf-8')
            # base64 decode
            content = base64.b64decode(content)
        return CertificateStore.parseCertificateFromBER(content)

    @staticmethod
    def parseCertificateFromBER(ber):
        return CertificateStore.parseCertificateFromInputStream(asn1.InputStream(ber))

    @staticmethod
    def parseCertificateFromInputStream(stream):
        return x509certificate.X509Certificate(stream)

    def __init__(self):
        self._store = {}
        self._order = []

    def _addCert(self, cert):
        # hash subject -> cert._subject().toBER()
        hash = self.hashSubject(cert._subject().toBER())
        if hash not in self._order:
            self._store[hash] = cert
            self._order += [hash]

    def hashSubject(self, msg):
        m = hashlib.sha256()
        m.update(msg)
        return m.hexdigest()

    def addCertificateFromFile(self, filename):
        cert = CertificateStore.parseCertificateFromFile(filename)
        self._addCert(cert)

    def addCertificatesFromDirectory(self, directory):
        for filename in os.listdir(directory):
            if not os.path.isfile(os.path.join(directory, filename)):
                continue
            absFilename = os.path.join(directory, filename)
            print('Importing certificate from ' + str(absFilename))
            self.addCertificateFromFile(absFilename)

    def addCertificateFromBER(self, ber):
        cert = CertificateStore.parseCertificateFromBER(ber)
        self._addCert(cert)
