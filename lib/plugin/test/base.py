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

# TLS SAK imports
from lib.connection import Connection_Exception
from lib.plugin.test import Active_Test_Plugin
from lib.tls import TLS_VERSIONS
from lib.tls.tlsciphersuites import TLS_CipherSuite_Database
from lib.tls.tlscompressionmethods import TLS_CompressionMethod_Database
from lib.tls.tlsconnection import TLS_Connection
from lib.tls.tlsexceptions import TLS_Alert_Exception

class Parameter_Pretest(Active_Test_Plugin):
    def instancable(self):
        return True

    def init(self, storage, args):
        super().init(storage, args)

        sto = storage.get(type(self).__name__)

        # parse protocols
        if len(args.tlsprotocol) < 1:
            args.tlsprotocol = ['*']

        protocols = []
        for pitem in args.tlsprotocol:
            if pitem == '*':
                toadd = sorted(list(TLS_VERSIONS.keys()))
            elif pitem in TLS_VERSIONS.keys():
                toadd = [pitem]
            else:
                toadd = []

            for item in toadd:
                if item not in protocols:
                    protocols += [item]

        sto.put('protocols.selected', protocols)

    def prepareArguments(self, parser):
        parser.add_argument('-tp', '--tls-protocol', default=[], help='choose protocol to connect with', choices=list(TLS_VERSIONS.keys()) + ['*'], dest='tlsprotocol', action='append')

    def execute(self, connection, storage):
        sto = storage.get(type(self).__name__)
        protocols = sto.get('protocols.selected', [])

        available_protocols = []

        # connect and test
        for protocol in protocols:
            self.output.logInfo('Checking for protocol ' + protocol + ' ...')
            try:
                with connection:
                    tls_connection = TLS_Connection(connection)
                    tls_connection.setClientProtocolVersion(protocol)
                    tls_connection.setAvailableCipherSuites(TLS_CipherSuite_Database.getInstance().getAllCipherSuites())
                    tls_connection.setAvailableCompressionMethods(TLS_CompressionMethod_Database.getInstance().getAllCompressionMethods())
                    tls_connection.connect()

                    version = tls_connection.getServerProtocolVersion()
                    if version != protocol:
                        continue

                    # available protocol identified
                    available_protocols += [protocol]
            except TLS_Alert_Exception as e:
                if e.description != 'handshake_failure':
                    self.output.logError(str(e))

            except Connection_Exception as e:
                self.output.logError('Error while connecting: ' + str(e))
                connection.close()

        sto.put('protocols.available', available_protocols)
