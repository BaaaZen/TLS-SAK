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
