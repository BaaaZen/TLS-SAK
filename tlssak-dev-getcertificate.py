# TLS-SAK - TLS Swiss Army Knife
# https://github.com/RBT-itsec/TLS-SAK
# Copyright (C) 2016 by Mirko Hansen / ARGE Rundfunk-Betriebstechnik
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

# generic imports
import argparse
from pyasn1_modules import rfc2459
from pyasn1.codec.ber import decoder

# TLS SAK imports
from lib.connection import Connection_Exception
from lib.connection.starttls import Connection_STARTTLS_FTP
from lib.connection.starttls import Connection_STARTTLS_SMTP
from lib.connection.tcpsocket import Connection_TCP_Socket
from lib.tls.tlsciphersuites import TLS_CipherSuite_Database
from lib.tls.tlscompressionmethods import TLS_CompressionMethod_Database
from lib.tls.tlsconnection import TLS_Connection
from lib.tls.tlsexceptions import TLS_Alert_Exception

# presets
starttls_supported = ['smtp', 'ftp']

def main():
    # prepare argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--starttls', help='use STARTTLS for specific protocol', choices=starttls_supported, dest='starttls')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to be checked', dest='port')
    parser.add_argument('host', help='hostname or IP address of target system')
    args = parser.parse_args()

    # create connection object
    if args.starttls == 'ftp':
        connection = Connection_STARTTLS_FTP(args.host, args.port)
    elif args.starttls == 'smtp':
        connection = Connection_STARTTLS_SMTP(args.host, args.port)
    else:
        connection = Connection_TCP_Socket(args.host, args.port)


    protocol = 'TLSv1.3'
    try:
        cipher_suites = TLS_CipherSuite_Database.getInstance().getAllCipherSuites()
        with connection:
            tls_connection = TLS_Connection(connection)
            tls_connection.setClientProtocolVersion(protocol)
            tls_connection.setAvailableCipherSuites(cipher_suites)
            tls_connection.setAvailableCompressionMethods(TLS_CompressionMethod_Database.getInstance().getAllCompressionMethods())
            tls_connection.connect()

            server_certificates = tls_connection.getServerCertificates()
            i = 0

            for c in server_certificates:
                i += 1
                dec = decoder.decode(c.toBER(), asn1Spec=rfc2459.Certificate())[0]
                cert = dec.getComponentByName("tbsCertificate")
                # print(dec.prettyPrint())
                # print(str(dec.getComponentByName("tbsCertificate")))
                # print(str(dec.getComponentByName('signatureAlgorithm')))
                for x in cert.getComponentByName('subject'):
                    print('x: ' + x.prettyPrint())

                with open(args.host + '_' + str(i) + '.crt', 'wb') as f:
                    f.write(c.toPEM())
    except TLS_Alert_Exception as e:
        if e.description != 'handshake_failure':
            print(str(e))

    except Connection_Exception as e:
        print('Error while connecting: ' + str(e))
        connection.close()



if __name__ == '__main__':
    main()
