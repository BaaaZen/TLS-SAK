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
from lib.certificate import certstore
from lib.connection import Connection_Exception
from lib.plugin.test import Active_Test_Plugin
from lib.plugin.test.base import Parameter_Pretest
from lib.tls.tlsciphersuites import TLS_CipherSuite_Database
from lib.tls.tlscompressionmethods import TLS_CompressionMethod_Database
from lib.tls.tlsconnection import TLS_Connection
from lib.tls.tlsexceptions import TLS_Alert_Exception
from lib.tls.tlsextensions import TLS_Extension_ServerName

class Fetch_Certificate(Active_Test_Plugin):
    def instancable(self):
        return True

    def init(self, storage, args):
        super().init(storage, args)

        sto = storage.get(type(self).__name__)
        sto.put('active', args.certificate)
        sto.put('sni', args.sni)

    def prepareArguments(self, parser):
        parser.add_argument('-c', '--certificate', help='process certificate sent from server', dest='certificate', action='store_true')
        parser.add_argument('-sn', '--sni', default=[], help='transmit SNI (server name indication)', dest='sni', action='append')

    def execute(self, connection, storage):
        basic_sto = storage.get(Parameter_Pretest.__name__)
        protocols = basic_sto.get('protocols.available', [])

        sto = storage.get(type(self).__name__)
        if not sto.get('active', False):
            return

        sni_names = sto.get('sni', [])
        if sni_names is None:
            sni_names = []

        protocol = protocols[0]
        self.output.logInfo('Fetching certificate with ' + protocol + ' ...')
        try:
            with connection:
                tls_connection = TLS_Connection(connection)
                tls_connection.setClientProtocolVersion(protocol)
                tls_connection.setAvailableCipherSuites(TLS_CipherSuite_Database.getInstance().getAllCipherSuites())
                tls_connection.setAvailableCompressionMethods(TLS_CompressionMethod_Database.getInstance().getAllCompressionMethods())
                if len(sni_names) > 0:
                    # add SNI to TLS extensions
                    ext_sni = TLS_Extension_ServerName(server_names=sni_names)
                    tls_connection.setAvailableExtensions([ext_sni])
                tls_connection.connect()

                server_certificates = tls_connection.getServerCertificates()

                # put server certificates in a cert store
                store = certstore.CertificateStore()
                for server_cert in server_certificates:
                    store.addCertificateFromBER(server_cert.toBER())

                # output result
                sto.append('certificate', store)
                self.output.logInfo(' * certificates fetched and stored')
        except TLS_Alert_Exception as e:
            if e.description != 'handshake_failure':
                self.output.logError(str(e))

        except Connection_Exception as e:
            self.output.logError('Error while connecting: ' + str(e))
            connection.close()
