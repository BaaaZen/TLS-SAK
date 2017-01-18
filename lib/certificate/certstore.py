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
import pickle

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

    @staticmethod
    def hashSubject(msg):
        m = hashlib.sha256()
        m.update(msg)
        return m.hexdigest()

    def __init__(self, cacheDir=None, cachePerFile=True):
        self._store = {}
        self._order = []
        self._cacheDir = cacheDir
        self._cachePerFile = cachePerFile

        self._validateCacheDir(cacheDir)

    def _validateCacheDir(self, dir):
        if dir == None:
            return
        if not os.path.exists(dir):
            self._validateCacheDir(os.path.abspath(os.path.join(dir, os.pardir)))
            os.mkdir(dir)
        if not os.path.isdir(dir):
            raise Exception('invalid directory for certificate cache: ' + dir + ' is not a directory!')

    def _saveCache(self):
        if self._cacheDir == None or self._cachePerFile:
            return
        filename = os.path.join(self._cacheDir, 'certs.cache')
        # print('saving cache to ' + filename)
        with open(filename, 'wb') as f:
            pickle.dump([self._store, self._order], f)

    def _loadCache(self):
        if self._cacheDir == None or self._cachePerFile:
            return

        filename = os.path.join(self._cacheDir, 'certs.cache')
        if not os.path.exists(filename) or not os.path.isfile(filename):
            return
        with open(filename, 'rb') as f:
            [self._store, self._order] = pickle.load(f)

    def addCert(self, cert):
        # hash subject -> cert._subject().toBER()
        hash = self.hashSubject(cert._subject().toBER())
        if hash not in self._order:
            self._store[hash] = cert
            self._order += [hash]
            self._saveCache()

    def getCertificateByHash(self, hash):
        if hash in self._store:
            return self._store[hash]
        return None

    def getCertificateByID(self, id):
        if id < 0 or id >= len(self._order):
            return None
        return self._store[self._order[id]]

    def addCertificateFromFile(self, filename):
        cert = None

        # first check if we have cached the cert as pickle object?
        if self._cacheDir != None and self._cachePerFile:
            cachefilename = os.path.join(self._cacheDir, 'cert-' + CertificateStore.hashSubject(os.path.abspath(filename).encode('utf-8')) + '.cache')
            if os.path.exists(cachefilename) and os.path.isfile(cachefilename):
                with open(cachefilename, 'rb') as f:
                    cert = pickle.load(f)

        # otherwise (slower) parse certificate
        if cert == None:
            print('Importing certificate from ' + str(filename))
            cert = CertificateStore.parseCertificateFromFile(filename)

        # if necessary store parsed cert as pickle in cache file
        if self._cacheDir != None and self._cachePerFile:
            if not os.path.exists(cachefilename):
                with open(cachefilename, 'wb') as f:
                    pickle.dump(cert, f)

        self.addCert(cert)

    def addCertificatesFromDirectory(self, directory):
        for filename in os.listdir(directory):
            if not os.path.isfile(os.path.join(directory, filename)):
                continue
            absFilename = os.path.join(directory, filename)
            self.addCertificateFromFile(absFilename)

    def addCertificateFromBER(self, ber):
        cert = CertificateStore.parseCertificateFromBER(ber)
        self.addCert(cert)
