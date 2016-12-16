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
from lib.connection.starttls import Connection_STARTTLS_FTP
from lib.connection.starttls import Connection_STARTTLS_SMTP
from lib.connection.tcpsocket import Connection_TCP_Socket
from lib.plugin import Plugin
from lib.plugin import Plugin_Storage
from lib.plugin.test import Active_Test_Plugin

# presets
starttls_supported = ['smtp', 'ftp']

def main():
    # load plugins
    plugins = Plugin.findPlugins()
    Plugin.loadPlugins(plugins)

    # prepare argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--starttls', help='use STARTTLS for specific protocol', choices=starttls_supported, dest='starttls')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to be checked', dest='port')
    parser.add_argument('host', help='hostname or IP address of target system')
    Plugin.executeLambda(None, lambda p, parser=parser: p.prepareArguments(parser))
    args = parser.parse_args()

    # create storage
    storage = Plugin_Storage()

    # init plugins
    Plugin.executeLambda(None, lambda p, stor=storage, args=args: p.init(stor, args))

    # create connection object
    if args.starttls == 'ftp':
        connection = Connection_STARTTLS_FTP(args.host, args.port)
    elif args.starttls == 'smtp':
        connection = Connection_STARTTLS_SMTP(args.host, args.port)
    else:
        connection = Connection_TCP_Socket(args.host, args.port)

    # execute all active tests
    Plugin.executeLambda(Active_Test_Plugin, lambda p, c=connection, stor=storage: p.execute(c, stor))

    # deinit plugins:
    Plugin.executeLambda(None, lambda p, stor=storage: p.deinit(stor))

if __name__ == '__main__':
    main()
