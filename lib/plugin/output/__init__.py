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

# TLS SAK imports
from lib.plugin import Plugin
from lib.plugin import Plugin_Exception

class Output_Plugin(Plugin):
    def configure(self, args=None):
        pass

    def logVerbose(self, msg):
        pass

    def logInfo(self, msg):
        pass

    def logError(self, msg):
        pass

    def reportCiphersuite(self, cs):
        pass

class Collective_Output_Plugin(Output_Plugin):
    def __init__(self):
        self.subPlugins = []

    def addOutputPlugin(self, plugin):
        if not issubclass(type(plugin), Output_Plugin):
            raise Plugin_Exception('Collective_Output_Plugin expects an Output_Plugin for adding')
        self.subPlugins += [plugin]

    def configure(self, args=None):
        for p in self.subPlugins:
            p.configure(args=args)

    def logVerbose(self, msg):
        for p in self.subPlugins:
            p.logVerbose(msg=msg)

    def logInfo(self, msg):
        for p in self.subPlugins:
            p.logInfo(msg=msg)

    def logError(self, msg):
        for p in self.subPlugins:
            p.logError(msg=msg)

    def reportCiphersuite(self, cs):
        for p in self.subPlugins:
            p.reportCiphersuite(cs=cs)
