# generic imports
import argparse
import sys

# TLS SAK imports
from lib.connection import Connection_Exception
from lib.connection.tcpsocket import Connection_TCP_Socket
from lib.tls.tlsconnection import TLS_Connection

starttls_supported = ['smtp', 'ftp']

def client(args):
    # create connection object
    connection = Connection_TCP_Socket(args.host, args.port)

    # connect and test
    try:
        with connection as c:
            tls_connection = TLS_Connection(c)
            tls_connection.setClientProtocolVersion('TLSv1.2')
            tls_connection.connect()

    except Connection_Exception as e:
        print('Error while connecting: ' + str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--starttls', help='use STARTTLS for specific protocol', choices=starttls_supported, dest='starttls')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to be checked', dest='port')
    parser.add_argument('host', help='hostname or IP address of target system')
    args = parser.parse_args()

    client(args)
