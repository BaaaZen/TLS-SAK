from lib.certificate import asn1

# definition from https://tools.ietf.org/html/rfc5280
class X509(asn1.ASN1):
    oids = {
        # encryption / hash / signature functions
        '1.2.840.113549.1.1.1': 'rsaEncryption',
        '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
        # name properties
        '2.5.4.3': 'CN',
        '2.5.4.6': 'C',
        '2.5.4.10': 'O',
        # x509 extensions
        '2.5.29.17': 'subjectAltName'
    }

    def __init__(self):
        super().__init__(X509.oids)

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
        tbscertificate.addParseItem('signature', self.pAlgorithmIdentifier())
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
        time.addParseItem('utcTime', asn1.UTCTime())
        time.addParseItem('generalTime', asn1.GeneralizedTime())
        return time

    def pUniqueIdentifier(self):
        return asn1.BitString()

    def pSubjectPublicKeyInfo(self):
        subjectpublickeyinfo = asn1.Sequence()
        subjectpublickeyinfo.addParseItem('algorithm', self.pAlgorithmIdentifier())
        subjectpublickeyinfo.addParseItem('subjectPublicKey', asn1.BitString())
        return subjectpublickeyinfo

    def pExtensions(self):
        extensions = asn1.SequenceOf()
        extensions.setParseValidSize(1, None)
        extensions.setParseItem(self.pExtension())
        return extensions

    def pExtension(self):
        extension = asn1.Sequence()
        extension.addParseItem('extnID', asn1.ObjectIdentifier(self))
        extension.addParseItem('critical', asn1.Boolean(), default=False)
        extension.addParseItem('extnValue', asn1.OctetString())
        return extension

    # definition in 4.1.1.2
    def pAlgorithmIdentifier(self):
        algorithmidentifier = asn1.Sequence()
        algorithmidentifier.addParseItem('algorithm', asn1.ObjectIdentifier(self))
        algorithmidentifier.addParseItem('parameters', asn1.Any(), optional=True)
        return algorithmidentifier

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
        relativedistinguishedname.setParseValidSize(1, None)
        relativedistinguishedname.setParseItem(self.pAttributeTypeAndValue())
        return relativedistinguishedname

    def pAttributeTypeAndValue(self):
        attributetypeandvalue = asn1.Sequence()
        attributetypeandvalue.addParseItem('type', self.pAttributeType())
        attributetypeandvalue.addParseItem('value', self.pAttributeValue())
        return attributetypeandvalue

    def pAttributeType(self):
        return asn1.ObjectIdentifier(self)

    def pAttributeValue(self):
        return asn1.Any()

    # definition in A.1
    def pDirectoryString(self):
        directorystring = asn1.Choice()
        # directorystring.addParseItem('teletexString', ...)
        directorystring.addParseItem('printableString', asn1.PrintableString())
        # directorystring.addParseItem('universalString', asn1.UniversalString())
        directorystring.addParseItem('utf8String', asn1.UTF8String())
        directorystring.addParseItem('bmpString', asn1.BMPString())
        return directorystring

    # definition in 4.2.1.6
    def pSubjectAltName(self):
        return self.pGeneralNames()

    def pGeneralNames(self):
        generalnames = asn1.SequenceOf()
        generalnames.setParseValidSize(1, None)
        generalnames.setParseItem(self.pGeneralName())
        return generalnames

    def pGeneralName(self):
        generalname = asn1.Choice()
        generalname.addParseItem('otherName', self.pOtherName(), index=0)
        generalname.addParseItem('rfc822Name', asn1.IA5String(), index=1)
        generalname.addParseItem('dNSName', asn1.IA5String(), index=2)
        # generalname.addParseItem('x400Address', asn1.IA5String(), index=3)
        generalname.addParseItem('directoryName', self.pName(), index=4)
        generalname.addParseItem('ediPartyName', self.pEDIPartyName(), index=5)
        generalname.addParseItem('uniformResourceIdentifier', asn1.IA5String(), index=6)
        generalname.addParseItem('iPAddress', asn1.OctetString(), index=7)
        generalname.addParseItem('registeredID', asn1.ObjectIdentifier(), index=8)
        return generalname

    def pOtherName(self):
        othername = asn1.Sequence()
        othername.addParserItem('type-id', asn1.ObjectIdentifier())
        othername.addParserItem('value', asn1.Any(), index=0, explicit=True)
        return othername

    def pEDIPartyName(self):
        edipartyname = asn1.Sequence()
        edipartyname.addParserItem('nameAssigner', self.pDirectoryString(), index=0, implicit=True, optional=True)
        edipartyname.addParserItem('partyName', self.pDirectoryString(), index=1, implicit=True)
        return edipartyname
