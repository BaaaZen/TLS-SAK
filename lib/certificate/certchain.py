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

from lib.certificate import certstore

class CertificateChainEntry:
    def __init__(self, cert):
        self.cert = cert

        self.issuer = None

        self.isVerified = False
        self.isStart = False
        self.isIssuerRoot = False
        self.isIssuerMissing = False
        self.isSelfSigned = False


class CertificateChain:
    def __init__(self, rootStore=None, intermediateStore=None, currentStore=None, startCert=None):
        self._chainList = []

        self._rootStore = rootStore
        self._intermediateStore = intermediateStore
        self._currentStore = currentStore

        self._processCertificate(startCert, True)
        self._verifyChain()

    def _processCertificate(self, cert, isStart=False):
        if cert == None:
            return
        if self.isInChain(cert):
            # -> emergency break -> loop!
            return

        ce = CertificateChainEntry(cert)
        ce.isStart = isStart
        self._chainList += [ce]

        if cert._subject().toBER() == cert._issuer().toBER():
            # this certificate is self signed!
            ce.isSelfSigned = True
            ce.issuer = cert
        else:
            hash = certstore.CertificateStore.hashSubject(cert._issuer().toBER())

            ce.issuer = None
            if self._rootStore != None:
                ce.issuer = self._findCertificate(self._rootStore, hash)
            if ce.issuer == None:
                # not in root store
                if self._currentStore != None:
                    ce.issuer = self._findCertificate(self._currentStore, hash)
                if ce.issuer == None:
                    # not in current store
                    ce.isIssuerMissing = True
                    if self._intermediateStore != None:
                        ce.issuer = self._findCertificate(self._intermediateStore, hash)
                else:
                    # add intermediate certificate to intermediate cert store
                    self._intermediateStore.addCert(ce.issuer)
            else:
                ce.isIssuerRoot = True

        if ce.issuer != None:
            self._processCertificate(ce.issuer)

    def _findCertificate(self, store, hash):
        if store == None:
            return None
        if hash == None:
            return None
        return store.getCertificateByHash(hash)

    def _verifyChain(self):
        for item in self._chainList:
            v = item.cert.verifySignature(item.issuer)
            print('cert: ' + str(item.cert.getSubject()))
            print('issuer: ' + str(item.issuer.getSubject()))
            print('valid notBefore: ' + str(item.cert.getValidityNotBefore()))
            print('valid notAfter: ' + str(item.cert.getValidityNotAfter()))
            print('verified: ' + str(v))
            item.isVerified = v

    def isInChain(self, cert):
        for item in self._chainList:
            if item.cert == cert:
                return True
        return False
