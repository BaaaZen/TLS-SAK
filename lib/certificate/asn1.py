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

import binascii

class ParserException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'ASN1 Parser Exception: ' + str(self.msg)


class InputStream:
    def __init__(self, s):
        self._s = s
        self._ptr = 0

    def readByte(self):
        b = self.readBytes()
        if b == None:
            return None
        else:
            return b[0]

    def readBytes(self, l=1):
        if self._ptr >= len(self._s):
            return None
        s = self._s[self._ptr:self._ptr+l]
        #print('read: ' + str(self._ptr) + '+' + str(l) + ' [' + str(s) + ']')
        self._ptr += l
        return s

    def hasMoreBytesToRead(self):
        return True

    def length(self):
        return -1

    def __str__(self):
        return self.__class__.__name__ + '[' + str(self._ptr) + '/' + str(len(self._s)) + ']'

class DelimitedInputStream(InputStream):
    def __init__(self, stream, len=-1):
        self._stream = stream
        self._ptr = 0
        self._len = len

    def readByte(self):
        #print('1ptr [' + self.__class__.__name__ + ']: ' + str(self._ptr))
        if not self.hasMoreBytesToRead():
            #print('eof (' + str(self._len) + ')')
            return None
        self._ptr += 1
        return self._stream.readByte()

    def readBytes(self, l=1):
        #print('xptr [' + self.__class__.__name__ + ']: ' + str(self._ptr))
        if not self.hasMoreBytesToRead():
            #print('eof (' + str(self._len) + ')')
            return None
        if self._len != -1 and self._ptr + l > self._len:
            l = self._len - self._ptr
        self._ptr += l
        return self._stream.readBytes(l)

    def hasMoreBytesToRead(self):
        if self._len == -1:
            return True
#        print('      [decide: ' + str(self._ptr) + ' < ' + str(self._len) + ' ?]')
        return self._ptr < self._len

    def length(self):
        return self._len

    def __str__(self):
        x = str(self._stream).split('\n')
        x = [' ' + y for y in x]
        x = [self.__class__.__name__ + '[' + str(self._ptr) + '/' + str(self._len) + ']'] + x
        return '\n'.join(x)

class BufferedInputStream(InputStream):
    def __init__(self, stream):
        self._stream = stream
        self._buffer = b''
        self._record = False
        self._ptr = 0

    def mark(self):
        self._record = True
        if len(self._buffer) > 0 and self._ptr > 0:
            self._buffer = self._buffer[self._ptr:]
        self._ptr = 0

    def unmark(self):
        if not self._record:
            raise Exception('buffer was not marked! unmarking not possible.')
        self._record = False
        if len(self._buffer) > 0 and self._ptr > 0:
            self._buffer = self._buffer[self._ptr:]
        self._ptr = 0

    def isMarked(self):
        return self._record

    def goBack(self):
        if not self._record:
            raise Exception('buffer was not marked! going back not possible.')
        self._record = False
        self._ptr = 0

    def readBytes(self, l=1):
        b = b''
        if self._ptr < len(self._buffer):
            # do we have some bytes in the buffer?
            bfl = min(len(self._buffer) - self._ptr, l)
            b += self._buffer[self._ptr:self._ptr + bfl]
            self._ptr += bfl
            l -= bfl
            if not self._record:
                self._buffer = self._buffer[self._ptr:]
                self._ptr = 0

        if l > 0:
            # there are still bytes left that are not buffered
            b2 = self._stream.readBytes(l)
            if b2 is None and len(b) < 1:
                return None
            b += b2
            if self._record:
                self._buffer += b2
                self._ptr += len(b2)

        return b

    def hasMoreBytesToRead(self):
        if not self._stream.hasMoreBytesToRead():
            if not self._record and self._ptr < len(self._buffer):
                return True
        return self._stream.hasMoreBytesToRead()

    def length(self):
        return self._stream.length()

    def __str__(self):
        x = str(self._stream).split('\n')
        x = [' ' + y for y in x]
        x = [self.__class__.__name__ + '[' + str(self._ptr) + '/' + str(self._record) + ']'] + x
        return '\n'.join(x)


class ASN1:
    def pRoot(self):
        pass

    def parse(self, stream):
        tree = self.pRoot()
        tree.parse(stream)



class BaseElement:
    def getTagValue(self):
        # abstract method, needs to be implemented by each object type
        pass

    def parseContent(self, stream):
        # abstract method, needs to be implemented by each object type
        pass

    def clone(self):
        # abstract method
        return self.__class__()

    def parsePacket(self, stream):
        # first parse length
        fb = stream.readByte()
        if fb is None:
            raise ParserException('missing object length: end of file')

        if fb == 0x80:
            # length is not defined, so we need to cache
            cache = stream.readBytes(2)
            if cache is None:
                raise ParserException('missing content for caching: end of file')

            while True:
                if cache[-2:] == b'\x00\x00':
                    return DelimitedInputStream((cache[:-2]), len(cache)-2)
                b = stream.readBytes(1)
                if b is None:
                    raise ParserException('missing content for caching: end of file')
                cache += b
        elif fb & 0x80 == 0:
            # the length value is lower than 128, so this byte is the length of the object
            return DelimitedInputStream(stream, fb)
        else:
            # the length value is higher than 128, so the first 7 bits describe the length of the
            # following length field
            flen = fb & 0x7F
            lb = stream.readBytes(flen)
            l = 0
            for b in lb:
                l <<= 8
                l |= b
            return DelimitedInputStream(stream, l)

    def parse(self, stream, softfail=False, tag=None):
        print('parsing [' + self.__class__.__name__ + ']')
        if tag is None:
            tag = self.getTagValue()
        rtag = stream.readByte()
        # TODO: is that a good idea?
        # if type(stream) is BufferedInputStream:
        #     if stream.isMarked():
        #         stream.unmark()
        if tag != rtag:
            if softfail:
                return False
            else:
                raise ParserException('invalid tag found: ' + hex(rtag) + ' instead of ' + hex(tag))
        #print(self.__class__.__name__ + ' [' + str(stream.length()) + ']')
        subStream = self.parsePacket(stream)
        print(' -> stream: ' + subStream.__class__.__name__ + ' [' + str(subStream.length()) + ']')
        self.parseContent(subStream)
        return True

    def __str__(self):
        return '(unknown)'


class TransparentElement(BaseElement):
    def __init__(self, subElement):
        self._subElement = subElement

    def clone(self):
        return self.__class__(subElement.clone())

    def parseContent(self, stream):
        self._subElement.parse(stream)


class BitString(BaseElement):
    def __init__(self):
        self._value = b''

    def getTagValue(self):
        return 0x03

    def parseContent(self, stream):
        self._value = stream.readBytes(stream.length())

    def __str__(self):
        return 'BIT STRING(' + binascii.hexlify(self._value).decode('utf-8') + ')'


class Boolean(BaseElement):
    def __init__(self):
        self._value = False

    def getTagValue(self):
        return 0x01

    def parseContent(self, stream):
        if stream.length() != 1:
            raise ParserException('BOOLEAN object has invalid length: ' + str(stream.length()) + ' instead of 1')
        v = stream.readByte()
        if v is None:
            raise ParserException('missing content: end of file')

        self._value = (v != 0)

    def isTrue(self):
        return self._value

    def __str__(self):
        return 'BOOLEAN(' + str(self._value) + ')'


class Integer(BaseElement):
    def __init__(self):
        self._value = 0
        self._parseValidValues = None

    def getTagValue(self):
        return 0x02

    def setParseValidValues(self, lst):
        self._parseValidValues = lst

    def parseContent(self, stream):
        if stream.length() < 1:
            raise ParserException('INTEGER object has invalid length: ' + str(stream.length()) + ' instead of at least 1')
        v = stream.readBytes(stream.length())
        if v is None:
            raise ParserException('missing content: end of file')

        sign = 1
        if v[0] & 0x80 == 0x80:
            sign = -1
            self._value |= (v[0] & 0x7F)
        elif v[0] != 0:
            self._value = v[0]

        for sv in v[1:]:
            self._value <<= 8
            self._value |= sv

        self._value *= sign

        if self._parseValidValues is not None:
            if self._value not in self._parseValidValues:
                raise ParserException('INTEGER has invalid value: ' + str(self._value) + ' not in ' + str(self._parseValidValues))

    def getInteger(self):
        return self._value

    def __str__(self):
        return 'INTEGER(' + str(self._value) + ')'


class Null(BaseElement):
    def __init__(self):
        pass

    def getTagValue(self):
        return 0x05

    def parseContent(self, stream):
        if stream.length() > 0:
            raise ParserException('NULL object has invalid length: ' + str(stream.length()) + ' instead of 0')

    def __str__(self):
        return 'NULL'


class ObjectIdentifier(BaseElement):
    def __init__(self):
        self._oid = None

    def getTagValue(self):
        return 0x06

    def parseContent(self, stream):
        if stream.length() < 3:
            raise ParserException('OBJECT IDENTIFIER needs at least 3 bytes')

        oid = []
        subValue = 0

        fb = stream.readByte()
        if fb is None:
            raise ParserException('missing content: end of file')

        # parse first byte of oid
        first = fb / 40
        second = fb % 40
        if first > 2:
            oid += [2]

            if fb & 0x80 != 0:
                if fb == 0x80:
                    # illegal leading zeros
                    raise ParserException('encoding error: OID may not have leading zero(s)')
                subValue = fb & 0x7F
                # TODO: <see details for this case *** below>
            else:
                oid += [second - 80]
        else:
            oid += [first]
            oid += [second]

        while stream.hasMoreBytesToRead():
            #print('  (setting: ' + str(stream) + ')')
            b = stream.readByte()
            #print('  (settings: ' + stream.__class__.__name__ + ' / ' + str(stream.hasMoreBytesToRead()) + ' / ' + str(b) + ' / ' + hex(b) + ')')
            if b == None:
                #print('NONE2: ' + stream.__class__.__name__)
                raise ParserException('missing content: end of file')

            if b & 0x80 != 0:
                if b == 0x80 and subValue == 0:
                    # illegal leading zeros
                    raise ParserException('encoding error: OID may not have leading zero(s)')

                subValue <<= 7
                subValue |= b & 0x7F
            else:
                if subValue != 0:
                    subValue <<= 7
                subValue |= b
                # TODO: maybe we need to substract 80 in case *** (see above)

                oid += [subValue]
                subValue = 0

        if subValue != 0:
            raise ParserException('encoding error? oid seems to be incomplete or invalid')

        self._oid = '.'.join([str(x) for x in oid])

    def getOID(self):
        return self._oid

    def __str__(self):
        return 'OBJECT IDENTIFIER(' + self._oid + ')'


class OctetString(BaseElement):
    def __init__(self):
        self._content = None

    def getTagValue(self):
        return 0x04

    def parseContent(self, stream):
        self._content = stream.readBytes(stream.length())
        if self._content is None:
            raise ParserException('missing content: end of file')

    def getOctetString(self):
        return self._content

    def __str__(self):
        return 'OCTET STRING(' + binascii.hexlify(self._content).decrypt('utf-8') + ')'


class BMPString(BaseElement):
    pass


class IA5String(BaseElement):
    pass


class PrintableString(BaseElement):
    pass


class UTF8String(BaseElement):
    pass


class UTCTime(BaseElement):
    pass


class GeneralizedTime(BaseElement):
    pass


class Sequence(BaseElement):
    def __init__(self):
        self._parseSubItems = []
        self._items = {}

    def getTagValue(self):
        return 0x30

    def clone(self):
        cl = self.__class__()
        for it in self._parseSubItems:
            it['subElement'] = it['subElement'].clone()
            cl._parseSubItems += [it]
        return cl

    def addParseItem(self, name, subElement, index=None, explicit=None, implicit=None, optional=False, default=None):
        item = {}
        item['name'] = name
        item['subElement'] = subElement
        # TODO: more validity checks!
        if index is not None:
            item['index'] = index
            if implicit and not explicit:
                item['implicit'] = True
            elif not implicit:
                item['subElement'] = TransparentElement(subElement)
            else:
                raise ParserException('invalid grammar: implicit and explicit may not be combined!')
        elif implicit or explicit:
            raise ParserException('invalid grammar: implicit or explicit may only be used in combination with an index!')

        item['optional'] = optional
        if default is not None:
            item['default'] = default
            item['optional'] = True

        self._parseSubItems += [item]

    def parseContent(self, stream):
        stream = BufferedInputStream(stream)
        for item in self._parseSubItems:
            if 'optional' in item:
                stream.mark()

            if 'index' in item:
                dtag = item['index']
                if 'implicit' in item:
                    dtag |= 0x80
                else:
                    dtag |= 0xA0
                psucc = item['subElement'].parse(stream, softfail=True, tag=dtag)
            else:
                psucc = item['subElement'].parse(stream)

            if not psucc:
                if 'optional' not in item:
                    raise ParserException('parser error: item not found')
                else:
                    stream.goBack()
                    continue


class SequenceOf(BaseElement):
    def __init__(self):
        self._parseTemplateElement = None
        self._items = []
        self._parseValidSizeMin = None
        self._parseValidSizeMax = None

    def getTagValue(self):
        return 0x30

    def clone(self):
        cl = self.__class__()
        # that should work in this case (any case where this may become a bug?)
        # otherwise we also need to clone here
        cl._parseTemplateElement = self._parseTemplateElement
        return cl

    def setParseValidSize(self, minv, maxv):
        self._parseValidSizeMin = minv
        self._parseValidSizeMax = maxv

    def setParseItem(self, item):
        self._parseTemplateElement = item

    def parseContent(self, stream):
        while stream.hasMoreBytesToRead():
            print(str(self._parseTemplateElement))
            item = self._parseTemplateElement.clone()
            item.parse(stream)


class SetOf(SequenceOf):
    def getTagValue(self):
        return 0x31


class Any(BaseElement):
    def __init__(self):
        self._rawTag = None
        self._rawContent = None
        self._element = None

    def parseContent(self, stream):
        self._rawContent = stream.readBytes(stream.length())

    def parse(self, stream, softfail=False, tag=None):
        print('parsing [' + self.__class__.__name__ + ']')
        rtag = stream.readByte()
        if tag is not None:
            if tag != rtag:
                if softfail:
                    return False
                else:
                    raise ParserException('invalid tag found: ' + hex(rtag) + ' instead of ' + hex(tag))

        subStream = self.parsePacket(stream)
        self.parseContent(subStream)
        return True

    def decodeAs(self, c):
        self._element = c()
        if self._rawTag != self._element.getTagValue():
            raise ParserException('decode error: class ' + str(c) + ' doesn\'t fit tag value')
        self._element.parseContent(InputStream(self._rawContent))


class Choice(BaseElement):
    def __init__(self):
        self._parseSubItems = []
        self._item = None

    def clone(self):
        cl = self.__class__()
        for it in self._parseSubItems:
            it['subElement'] = it['subElement'].clone()
            cl._parseSubItems += [it]
        return cl

    def addParseItem(self, name, subElement):
        item = {}
        item['name'] = name
        item['subElement'] = subElement

        self._parseSubItems += [item]

    def parse(self, stream, softfail=False, tag=None):
        print('parsing [' + self.__class__.__name__ + ']')
        stream = BufferedInputStream(stream)
        for item in self._parseSubItems:
            stream.mark()
            psucc = item['subElement'].parse(stream, softfail=True)

            if psucc:
                self._item = item['subElement']
                return True
            else:
                stream.goBack()
                continue

        raise ParserException('parser error: no valid choice found')
