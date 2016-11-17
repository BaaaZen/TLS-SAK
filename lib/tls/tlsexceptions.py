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

class TLS_Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Exception: ' + str(self.msg)

class TLS_Not_Implemented_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Not_Implemented_Exception: ' + str(self.msg)

class TLS_Malformed_Package_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Malformed_Package_Exception: ' + str(self.msg)

class TLS_Parser_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Parser_Exception: ' + str(self.msg)

class TLS_Protocol_Exception(TLS_Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'TLS_Protocol_Exception: ' + str(self.msg)

class TLS_Alert_Exception(TLS_Exception):
    def __init__(self, level, description):
        self.level = level
        self.description = description

    def __str__(self):
        return 'TLS Alert: [' + self.level + '] ' + self.description
