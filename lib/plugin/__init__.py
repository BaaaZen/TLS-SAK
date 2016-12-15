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

import lib.plugin

class Plugin:
    instances = []
    namedInstances = {}

    def prepareArguments(self, parser):
        pass

    def init(self, args):
        pass

    def deinit(self):
        pass

    @staticmethod
    def loadPlugin(plugin):
        instance = plugin()
        Plugin.instances += [instance]
        Plugin.namedInstances[type(instance).__name__] = instance
        return instance

    @staticmethod
    def executeLambda(pluginType=None, lambdaFunction=None):
        for instance in Plugin.instances:
            if pluginType is None or issubclass(type(instance), pluginType):
                lambdaFunction(instance)

    @staticmethod
    def getPlugin(plugin):
        if plugin not in Plugin.namedInstances:
            return None
        return Plugin.namedInstances[plugin]

class Plugin_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Plugin_Exception: ' + str(self.msg)
