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

from lib.certificate import asn1
from lib.certificate import signature
from lib.certificate.asn1structs import x509


class X509CertificateStructure:
    def __init__(self, stream):
        self._struct = x509.X509()
        self._x509certificate = self._struct.parse(stream)

    def _root(self):
        return self._x509certificate

    def _tbsCertificate(self):
        return self._root().get('tbsCertificate')

    def _version(self):
        return self._tbsCertificate().get('version')

    def _serialNumber(self):
        return self._tbsCertificate().get('serialNumber')

    def _signature(self):
        return self._tbsCertificate().get('signature')

    def _issuer(self):
        return self._tbsCertificate().get('issuer').getChoice()

    def _validity(self):
        return self._tbsCertificate().get('validity')

    def _subject(self):
        return self._tbsCertificate().get('subject').getChoice()

    def _subjectPublicKeyInfo(self):
        return self._tbsCertificate().get('subjectPublicKeyInfo')

    def _subjectPublicKeyAlgorithm(self):
        return self._subjectPublicKeyInfo().get('algorithm')

    def _subjectPublicKey(self):
        return self._subjectPublicKeyInfo().get('subjectPublicKey')

    def _issuerUniqueID(self):
        return self._tbsCertificate().get('issuerUniqueID')

    def _subjectUniqueID(self):
        return self._tbsCertificate().get('subjectUniqueID')

    def _extensions(self):
        return self._tbsCertificate().get('extensions')

    def _signatureAlgorithm(self):
        return self._root().get('signatureAlgorithm')

    def _signatureValue(self):
        return self._root().get('signatureValue')



class X509Certificate(X509CertificateStructure):
    def __init__(self, stream):
        super().__init__(stream)

    def _resolveNameObject(self, name):
        if type(name) is not asn1.SequenceOf:
            return None
        r = ''
        for seqRDNS in name:
            for item in seqRDNS:
                if type(item) is not asn1.Sequence:
                    continue
                if not item.get('value').hasDecoder():
                    item.get('value').setDecoder(self._struct.pDirectoryString())
                rs = item.get('type').getResolvedOID() + '=' + item.get('value').getElement().getChoice().getString()
                if r != '':
                    r += '/'
                r += rs
        return r

    def getSignatureAlgorithm(self):
        return self._signatureAlgorithm().get('algorithm').getResolvedOID()

    def getSignatureValue(self):
        return self._signatureValue().getValue()

    def getVersion(self):
        return self._version().getInteger()

    def getSerialNumber(self):
        return self._serialNumber().getInteger()

    def getSignature(self):
        return self._signature().get('algorithm').getResolvedOID()

    def getIssuer(self):
        return self._resolveNameObject(self._issuer())

    def getValidityNotBefore(self):
        return self._validity().get('notBefore').getChoice().getDate()

    def getValidityNotAfter(self):
        return self._validity().get('notAfter').getChoice().getDate()

    def getSubject(self):
        return self._resolveNameObject(self._subject())

    def getSubjectPublicKeyAlgorithm(self):
        return self._subjectPublicKeyAlgorithm().get('algorithm').getResolvedOID()

    def getSubjectPublicKey(self):
        return self._subjectPublicKey().getValue()

    # TODO: much more data

    def verifySignature(self, issuercert):
        # find used hash algorithm
        if self.getSignatureAlgorithm() == 'sha256WithRSAEncryption':
            ha = signature.SHA256()
        elif self.getSignatureAlgorithm() == 'sha1WithRSAEncryption':
            ha = signature.SHA1()
        else:
            # unknown hash algorithm
            return False
        h = ha.toBER(self._tbsCertificate().toBER())

        # find used signature algorithm
        if self.getSignatureAlgorithm() in ['sha1WithRSAEncryption', 'sha256WithRSAEncryption']:
            sa = signature.RSA(issuercert._subjectPublicKeyInfo().toBER())
        else:
            # unknown signature algorithm
            return False

        return sa.verify(h, self.getSignatureValue())
