from lib.connection import Connection_Exception
from lib.connection.tcpsocket import Connection_TCP_Socket

class Connection_STARTTLS(Connection_TCP_Socket):
    def __init__(self, host, port):
        super(Connection_STARTTLS, self).__init__(host, port)
        self.buffer = b''

    def connect(self):
        super(Connection_STARTTLS, self).connect()
        self.do_starttls()

    def do_starttls(self):
        pass

    def readLine(self):
        while not b'\n' in self.buffer:
            self._refillBuffer()

        [l, r] = self.buffer.split(b'\n', 1)

        self.buffer = r
        return l.decode('utf-8')

    def _refillBuffer(self):
        self.buffer += self.recv()


class Connection_STARTTLS_SMTP(Connection_STARTTLS):
    def do_starttls(self):
        # read first banner (starting with 220 ...)
        while True:
            line = self.readLine()
            if line.startswith('220 '):
                break
            if line.startswith('220'):
                continue
            raise Connection_Exception('error while receiving banner in STARTTLS/SMTP')

        # response with EHLO command
        self.send('EHLO tls-sak\r\n'.encode('utf-8'))

        # read capabilities (last one starts with 250 ...)
        hasSTARTTLS = False
        while True:
            line = self.readLine()
            if 'STARTTLS' in line:
                hasSTARTTLS = True
            if line.startswith('250 '):
                break
            if line.startswith('250'):
                continue
            raise Connection_Exception('error while receiving capabilities in STARTTLS/SMTP')

        # check if server accepts STARTTLS?
        if not hasSTARTTLS:
            raise Connection_Exception('server doesn\'t support STARTTLS')

        # send STARTTLS command
        self.send('STARTTLS\r\n'.encode('utf-8'))

        # read server response
        line = self.readLine()
        if not line.startswith('220 '):
            raise Connection_Exception('error while switching to TLS in STARTTLS/SMTP')


class Connection_STARTTLS_FTP(Connection_STARTTLS):
    def do_starttls(self):
        # read first banner (starting with 220 ...)
        while True:
            line = self.readLine()
            if line.startswith('220 '):
                break
            if line.startswith('220'):
                continue
            raise Connection_Exception('error while receiving banner in STARTTLS/FTP')

        # send AUTH TLS command
        self.send('AUTH TLS\r\n'.encode('utf-8'))

        # read server response
        line = self.readLine()
        if not line.startswith('234 '):
            raise Connection_Exception('error while switching to TLS in STARTTLS/FTP')
