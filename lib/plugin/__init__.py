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
import inspect
import os
import os.path
import sys

# TLS SAK imports
import lib.plugin

class Plugin:
    instances = []
    namedInstances = {}

    def prepareArguments(self, parser):
        pass

    def init(self, storage, args):
        storage.put(type(self).__name__, Plugin_Storage())

    def deinit(self, storage):
        pass

    def instancable(self):
        return False

    def dependencies(self):
        return []

    def priority(self):
        return 0

    @staticmethod
    def findPlugins(mod='lib.plugin'):
        inst = []

        modPath = mod.replace('.','/')
        if os.path.exists(modPath):
            for directory in os.listdir(modPath):
                if not os.path.isdir(os.path.join(modPath, directory)):
                    continue
                if directory.startswith(('.', '_')):
                    continue

                cll = Plugin.findPlugins(mod + '.' + directory)
                for cl in cll:
                    if cl not in inst:
                        inst += [cl]

            for fn in os.listdir(modPath):
                if not os.path.isfile(os.path.join(modPath, fn)):
                    continue
                if not fn.endswith('.py'):
                    continue
                else:
                    fn = fn[:-3]
                if fn.startswith(('.', '_')):
                    continue

                cll = Plugin.findPlugins(mod + '.' + fn)
                for cl in cll:
                    if cl not in inst:
                        inst += [cl]

        m = __import__(mod, fromlist=[''])
        for k in dir(m):
            attr = getattr(m, k)
            if inspect.isclass(attr) and issubclass(attr, Plugin) and attr().instancable():
                if attr not in inst:
                    inst += [attr]

        return inst

    @staticmethod
    def loadPlugins(plugins):
        Plugin.instances = []
        while True:
            nextPlugin = None
            nextPriority = sys.maxsize

            for plugin in plugins:
                if plugin.__name__ not in Plugin.namedInstances:
                    Plugin.namedInstances[plugin.__name__] = plugin()
                p = Plugin.namedInstances[plugin.__name__]
                dependencies = p.dependencies()
                if dependencies is not None:
                    depsFulfilled = True
                    for dep in dependencies:
                        if dep not in Plugin.instances:
                            depsFulfilled = False
                            break
                    if not depsFulfilled:
                        continue
                if p.priority() < nextPriority:
                    nextPlugin = plugin
                    nextPriority = p.priority()

            if nextPlugin is not None:
                plugins.remove(nextPlugin)
                instance = Plugin.namedInstances[nextPlugin.__name__]
                Plugin.instances += [instance]
            else:
                break

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

class Plugin_Storage:
    def __init__(self):
        self._storage = {}

    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        if name[:1] == '_':
            super().__setattr__(name, value)
        else:
            self.put(name, value)

    def get(self, key, default=None):
        if key not in self._storage:
            return default
        return self._storage[key]

    def put(self, key, value):
        self._storage[key] = value

    def init(self, key, value):
        self.put(key, value)
        return self.get(key, value)

    def append(self, key, value):
        self.put(key, self.get(key, []) + [value])

class Plugin_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Plugin_Exception: ' + str(self.msg)
