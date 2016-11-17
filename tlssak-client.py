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
import sys

# TLS SAK imports
from lib.connection import Connection_Exception
from lib.connection.starttls import Connection_STARTTLS_FTP
from lib.connection.starttls import Connection_STARTTLS_SMTP
from lib.connection.tcpsocket import Connection_TCP_Socket
from lib.tls import TLS_VERSIONS
from lib.tls.tlsciphersuites import TLS_CipherSuite_Database
from lib.tls.tlscompressionmethods import TLS_CompressionMethod_Database
from lib.tls.tlsconnection import TLS_Connection
from lib.tls.tlsexceptions import TLS_Alert_Exception

starttls_supported = ['smtp', 'ftp']

def client(args):
    # create connection object
    if args.starttls == 'ftp':
        connection = Connection_STARTTLS_FTP(args.host, args.port)
    elif args.starttls == 'smtp':
        connection = Connection_STARTTLS_SMTP(args.host, args.port)
    else:
        connection = Connection_TCP_Socket(args.host, args.port)

    # connect and test
    try:
        cipher_suites = TLS_CipherSuite_Database.getInstance().getAllCipherSuites()
        while True:
            with connection:
                tls_connection = TLS_Connection(connection)
                tls_connection.setClientProtocolVersion(args.tlsprotocol)
                tls_connection.setAvailableCipherSuites(cipher_suites)
                tls_connection.setAvailableCompressionMethods(TLS_CompressionMethod_Database.getInstance().getAllCompressionMethods())
                tls_connection.connect()

                chosen_cipher_suite = tls_connection.getChosenCipherSuite()

                # output result
                print(chosen_cipher_suite.name)

                # TODO: this is just a workaround, we need to use the same instances for the same cipher suite
                cipher_suites = [x for x in cipher_suites if x.cs_id != chosen_cipher_suite.cs_id]
    except TLS_Alert_Exception as e:
        if e.description != 'handshake_failure':
            print(str(e))

    except Connection_Exception as e:
        print('Error while connecting: ' + str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--starttls', help='use STARTTLS for specific protocol', choices=starttls_supported, dest='starttls')
    parser.add_argument('-tp', '--tls-protocol', default='TLSv1', help='choose protocol to connect with', choices=TLS_VERSIONS, dest='tlsprotocol')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to be checked', dest='port')
    parser.add_argument('host', help='hostname or IP address of target system')
    args = parser.parse_args()

    client(args)
