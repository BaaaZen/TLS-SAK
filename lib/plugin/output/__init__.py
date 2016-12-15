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

class Output_Log_Plugin(Plugin):
    def logVerbose(self, msg):
        pass

    def logInfo(self, msg):
        pass

    def logError(self, msg):
        pass

class Output_Ciphersuites_Plugin(Plugin):
    def reportCiphersuite(self, cs):
        pass

class Helper_Output_Plugin(Output_Log_Plugin,Output_Ciphersuites_Plugin):
    def instancable(self):
        return True

    def _helper(self, p, l):
        if p != self:
            l(p)

    def logVerbose(self, msg):
        l = lambda p, msg=msg: p.logVerbose(msg)
        l = lambda p, s=self, l=l: s._helper(p, l)
        Plugin.executeLambda(Output_Log_Plugin, l)

    def logInfo(self, msg):
        l = lambda p, msg=msg: p.logInfo(msg)
        l = lambda p, s=self, l=l: s._helper(p, l)
        Plugin.executeLambda(Output_Log_Plugin, l)

    def logError(self, msg):
        l = lambda p, msg=msg: p.logError(msg)
        l = lambda p, s=self, l=l: s._helper(p, l)
        Plugin.executeLambda(Output_Log_Plugin, l)

    def reportCiphersuite(self, cs):
        l = lambda p, msg=msg: p.reportCiphersuite(cs)
        l = lambda p, s=self, l=l: s._helper(p, l)
        Plugin.executeLambda(Output_Ciphersuites_Plugin, l)
