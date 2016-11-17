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

#TLS SAK imports
from lib.tls import TLS_VERSIONS
from lib.tls.tlsciphersuites import TLS_CipherSuite_Database
from lib.tls.tlsratings import TLS_Ratings_Database

def main():
    missing = []

    ratings = TLS_Ratings_Database.getInstance()
    for v in TLS_VERSIONS:
        r = ratings.getRating(param='protocol', setting=v, default=None)
        if r is None:
            missing += ['protocol=' + v]

    cipher_suites = TLS_CipherSuite_Database.getInstance().getAllCipherSuites()
    for cs in cipher_suites:
        kvpairs = {}
        kvpairs['kx'] = cs.kx
        kvpairs['au'] = cs.au
        kvpairs['enc'] = cs.enc
        kvpairs['bits'] = cs.bits
        kvpairs['mac'] = cs.mac

        for k in kvpairs:
            r = ratings.getRating(param=k, setting=kvpairs[k], default=None)
            dstr = k + '=' + kvpairs[k]
            if r is None and dstr not in missing:
                missing += [dstr]

    missing.sort()
    for m in missing:
        print(m)

if __name__ == '__main__':
    main()
