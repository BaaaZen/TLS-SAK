from lib.certificate import asn1

# definition from https://tools.ietf.org/html/rfc5280
class X509(asn1.ASN1):
    def pRoot(self):
        return self.pCertificate()


    # definition in 4.1
    def pCertificate(self):
        certificate = asn1.Sequence()
        certificate.addParseItem('tbsCertificate', self.pTBSCertificate())
        certificate.addParseItem('signatureAlgorithm', self.pAlgorithmIdentifier())
        certificate.addParseItem('signatureValue', asn1.BitString())
        return certificate

    def pTBSCertificate(self):
        tbscertificate = asn1.Sequence()
        tbscertificate.addParseItem('version', self.pVersion(), index=0, explicit=True, default=1)
        tbscertificate.addParseItem('serialNumber', self.pCertificateSerialNumber())
        tbscertificate.addParseItem('issuer', self.pName())
        tbscertificate.addParseItem('validity', self.pValidity())
        tbscertificate.addParseItem('subject', self.pName())
        tbscertificate.addParseItem('subjectPublicKeyInfo', self.pSubjectPublicKeyInfo())
        tbscertificate.addParseItem('issuerUniqueID', self.pUniqueIdentifier(), index=1, implicit=True, optional=True)
        tbscertificate.addParseItem('subjectUniqueID', self.pUniqueIdentifier(), index=2, implicit=True, optional=True)
        tbscertificate.addParseItem('extensions', self.pExtensions(), index=3, explicit=True, optional=True)
        return tbscertificate

    def pVersion(self):
        version = asn1.Integer()
        version.setParseValidValues([1,2,3])
        return version

    def pCertificateSerialNumber(self):
        return asn1.Integer()

    def pValidity(self):
        validity = asn1.Sequence()
        validity.addParseItem('notBefore', self.pTime())
        validity.addParseItem('notAfter', self.pTime())
        return validity

    def pTime(self):
        time = asn1.Choice()
        time.addParseItem('utcTime', self.pUTCTime())
        time.addParseItem('generalTime', self.pGeneralizedTime())
        return time

    def pUniqueIdentifier(self):
        return asn1.BitString()

    def pSubjectPublicKeyInfo(self):
        subjectpublickeyinfo = asn1.Sequence()
        subjectpublickeyinfo.addParseItem('algorithm', self.pAlgorithmIdentifier())
        subjectpublickeyinfo.addParseItem('subjectPublicKey', asn1.BitString())

    def pExtensions(self):
        extensions = asn1.SequenceOf()
        extensions.setParseValidSize(1,0)
        extensions.setParseItem(self.pExtension())

    def pExtensions(self):
        extension = asn1.Sequence()
        extension.addParseItem('extnID', asn1.ObjectIdentifier())
        extension.addParseItem('critical', asn1.Boolean(), default=False)
        extension.addParseItem('extnValue', asn1.OctetString())

    # definition in 4.1.2.4
    def pName(self):
        name = asn1.Choice()
        name.addParseItem('rdnSequence', self.pRDNSequence())
        return name

    def pRDNSequence(self):
        rdnsequence = asn1.SequenceOf()
        rdnsequence.setParseItem(self.pRelativeDistinguishedName())
        return rdnsequence

    def pRelativeDistinguishedName(self):
        relativedistinguishedname = asn1.SetOf()
        relativedistinguishedname.setParseValidSize(1,0)
        relativedistinguishedname.setParseItem(self.pAttributeTypeAndValue())
        return relativedistinguishedname

    def pAttributeTypeAndValue(self):
        attributetypeandvalue = asn1.Sequence()
        attributetypeandvalue.addParseItem('type', self.pAttributeType())
        attributetypeandvalue.addParseItem('value', self.pAttributeValue())
        return attributetypeandvalue

    def pAttributeType(self):
        return asn1.ObjectIdentifier()

    def pAttributeValue(self):
        return asn1.Any()
