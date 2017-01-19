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
from lib.certificate import x509extensions
from lib.certificate.asn1structs import x509


class X509StructureException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'X509 Structure Exception: ' + str(self.msg)


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
        return self._tbsCertificate().get('issuer')

    def _validity(self):
        return self._tbsCertificate().get('validity')

    def _subject(self):
        return self._tbsCertificate().get('subject')

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
        return self._tbsCertificate().get('extensions').getSelf()

    def _signatureAlgorithm(self):
        return self._root().get('signatureAlgorithm')

    def _signatureValue(self):
        return self._root().get('signatureValue')


class X509StructName:
    def __init__(self, x509cert, name):
        self._kvData = []

        if type(name) is not asn1.Choice:
            raise X509StructureException('Name structure root is ' + name.__class__.__name__ + ' instead of Choice')

        rdnsequence = name.getChoice()
        if type(rdnsequence) is not asn1.SequenceOf:
            raise X509StructureException('RDNSequence structure root is ' + name.__class__.__name__ + ' instead of SequenceOf')

        for relativedistinguishedname in rdnsequence:
            if type(relativedistinguishedname) is not asn1.SetOf:
                raise X509StructureException('RelativeDistinguishedName structure root is ' + name.__class__.__name__ + ' instead of SetOf')
            for attributetypeandvalue in relativedistinguishedname:
                if type(attributetypeandvalue) is not asn1.Sequence:
                    raise X509StructureException('AttributeTypeAndValue structure root is ' + name.__class__.__name__ + ' instead of Sequence')
                if not attributetypeandvalue.get('value').hasDecoder():
                    attributetypeandvalue.get('value').setDecoder(x509cert._struct.pDirectoryString())
                self._kvData += [attributetypeandvalue]

    def get(self, key, asOID=False):
        for kv in self._kvData:
            if asOID:
                skey = kv.get('type').getOID()
            else:
                skey = kv.get('type').getResolvedOID()

            if skey == key:
                return kv.get('value').getElement().getChoice().getString()
        return None

    def __str__(self):
        r = ''
        for item in self._kvData:
            rs = item.get('type').getResolvedOID() + '=' + item.get('value').getElement().getChoice().getString()
            if r != '':
                r += '/'
            r += rs
        return r


class X509StructExtensions:
    def __init__(self, x509cert, extensions):
        self._x509cert = x509cert
        self._extList = []

        if type(extensions) is not asn1.SequenceOf:
            raise X509StructureException('Extensions structure root is ' + extensions.__class__.__name__ + ' instead of SequenceOf')

        for extension in extensions:
            if type(extension) is not asn1.Sequence:
                raise X509StructureException('Extension structure root is ' + extension.__class__.__name__ + ' instead of Sequence')
            self._extList += [extension]

    def get(self, key, asOID=False):
        for ext in self._extList:
            if asOID:
                skey = ext.get('extnID').getOID()
            else:
                skey = ext.get('extnID').getResolvedOID()

            if skey == key:
                if ext.get('extnID').getOID() == x509extensions.X509ExtensionSubjectAltName.getOID():
                    # subjectAltName
                    return x509extensions.X509ExtensionSubjectAltName(self._x509cert, ext.get('extnValue').getOctetString(), ext.get('critical').isTrue())
                else:
                    # TODO: implement more extensions
                    # TODO: remove exception, just return None
                    raise Exception('not implemented')
        return None


class X509Certificate(X509CertificateStructure):
    def __init__(self, stream):
        super().__init__(stream)

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
        return X509StructName(self, self._issuer())

    def getValidityNotBefore(self):
        return self._validity().get('notBefore').getChoice().getDate()

    def getValidityNotAfter(self):
        return self._validity().get('notAfter').getChoice().getDate()

    def getSubject(self):
        return X509StructName(self, self._subject())

    def getSubjectPublicKeyAlgorithm(self):
        return self._subjectPublicKeyAlgorithm().get('algorithm').getResolvedOID()

    def getSubjectPublicKey(self):
        return self._subjectPublicKey().getValue()

    def getIssuerUniqueID(self):
        pass

    def getSubjectUniqueID(self):
        pass

    def getExtensions(self):
        return X509StructExtensions(self, self._extensions())

    def isValid(self):
        # check if current time (UTC) is between 'notBefore' and 'notAfter'
        now = datetime.datetime.utcnow()
        notBefore = self.getValidityNotBefore()
        notAfter = self.getValidityNotAfter()
        return notBefore <= now and now <= notAfter

    def isHostnameInCertificate(self, hostname):
        hostnames = []

        # first check if hostname matches hostname in subject
        subject = self.getSubject()
        cnSubject = subject.get('CN')
        if cnSubject != None:
            # there is no common name (CN) in subject of cert
            hostnames += [cnSubject]

        extensions = self.getExtensions()
        if extensions != None:
            extAltNames = extensions.get(x509extensions.X509ExtensionSubjectAltName.getOID(), asOID=True)
            if extAltNames != None:
                # append alternative hostnames
                hostnames += extAltNames.getNames()

        for hn in hostnames:
            if hn == hostname:
                # static hostname
                return True
            if hn.startswith('*.'):
                # wildcard!
                if hostname.endswith(hn[1:]):
                    return True

        return False

    # TODO: much more data

    def verifySignature(self, issuercert):
        # find used hash algorithm
        if self.getSignatureAlgorithm() == 'sha256WithRSAEncryption':
            ha = signature.SHA256()
        elif self.getSignatureAlgorithm() == 'sha1WithRSAEncryption':
            ha = signature.SHA1()
        else:
            # unknown hash algorithm
            print('unknown hash in signature algorithm: ' + self.getSignatureAlgorithm())
            return False
        h = ha.toBER(self._tbsCertificate().toBER())

        # find used signature algorithm
        if self.getSignatureAlgorithm() in ['sha1WithRSAEncryption', 'sha256WithRSAEncryption']:
            sa = signature.RSA(issuercert._subjectPublicKeyInfo().toBER())
        else:
            # unknown signature algorithm
            print('unknown signature algorithm: ' + self.getSignatureAlgorithm())
            return False

        return sa.verify(h, self.getSignatureValue())
