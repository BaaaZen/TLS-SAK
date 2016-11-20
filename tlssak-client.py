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

# TLS SAK imports
from lib.connection import Connection_Exception
from lib.connection.starttls import Connection_STARTTLS_FTP
from lib.connection.starttls import Connection_STARTTLS_SMTP
from lib.connection.tcpsocket import Connection_TCP_Socket
from lib.plugin import Plugin
import lib.plugin.test.ciphers

# presets
starttls_supported = ['smtp', 'ftp']
plugins = [lib.plugin.test.ciphers.List_Ciphers_Test]

def main():
    # init plugins
    for p in plugins:
        Plugin.loadPlugin(p)

    # prepare argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--starttls', help='use STARTTLS for specific protocol', choices=starttls_supported, dest='starttls')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to be checked', dest='port')
    parser.add_argument('host', help='hostname or IP address of target system')
    Plugin.preparePluginArguments(parser)
    args = parser.parse_args()

    client(args)

def client(args):
    # create connection object
    if args.starttls == 'ftp':
        connection = Connection_STARTTLS_FTP(args.host, args.port)
    elif args.starttls == 'smtp':
        connection = Connection_STARTTLS_SMTP(args.host, args.port)
    else:
        connection = Connection_TCP_Socket(args.host, args.port)




if __name__ == '__main__':
    main()
