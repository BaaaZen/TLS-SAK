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

# generic imports
import binascii

# TLS SAK imports
from lib.tls.tlsparameter import TLS_Extension

class TLS_Extension_ServerName(TLS_Extension):
    # Extension ID: 0
    # RFC: https://tools.ietf.org/html/rfc6066
    EXTENSIONTYPE = b'\x00\x00'
    
    def __init__(self, server_names=[]):
        self.server_names = server_names

    def serialize(self):
        if type(self.server_names) is not list and len(self.server_names) < 1:
            raise TLS_Exception('no server names for server_name extension specified')
        
        #  2 bytes  extension type      (0x0000 = server_name)
        #  2 bytes  size in bytes of content
        #  ---- content of extension ----
        #  2 bytes  size in bytes of following block
        #    1 byte   type of name        (0x00 = host_name)
        #    2 bytes  size in bytes of following block
        #     .. bytes  server name
        #  ---- end of content ----

        pkg_content = b''
        for server_name in self.server_names:
            server_name_content = server_name.encode('utf-8')
            server_name_size = struct.pack('!H', len(server_name_content))
            
            sni_content = b'\x00' + server_name_size + server_name_content
            sni_size = struct.pack('!H', len(sni_content))

            pkg_content += sni_size + sni_content

        pkg_size = struct.pack('!H', len(pkg_content))

        return EXTENSIONTYPE + pkg_size + pkg_content
