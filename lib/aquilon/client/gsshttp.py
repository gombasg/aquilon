# -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# ex: set expandtab softtabstop=4 shiftwidth=4:
#
# Copyright (C) 2008,2009,2010,2011,2013  Contributor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import base64
import socket
import errno
from six.moves.http_client import NotConnected  # pylint: disable=F0401

import kerberos

from aquilon.client.chunked import ChunkedHTTPConnection

class GSSSocket(socket.socket):
    """
    Generic client-side GSSAPI socket wrapper

    Supports enough functionality to be usable for Python's HTTP libraries.
    Does not support non-blocking mode.

    The Python kerberos module requires/produces Base64 encoded data, so this
    implementation does a lot of otherwise pointless Base64 conversions.
    """

    class _closedsocket(object):
        def __getattr__(self, name):
            raise OSError(errno.EBADF, 'Bad file descriptor')

    def __init__(self, sd, principal):
        super(GSSSocket, self).__init__(_sock=sd._sock)

        # socket.__init__() overwrites some methods, undo that here
        for method in socket._delegate_methods:
            try:
                delattr(self, method)
            except AttributeError:
                pass

        self._ctx = None
        self._sd = sd
        self._principal = principal
        self._readbuf = bytearray()
        self._decryptbuf = bytearray()
        self._connected = False

    def _read_pkt(self):
        if len(self._readbuf) >= 4:
            pkt_length = struct.unpack("!L", self._readbuf[0:4])[0]
        else:
            pkt_length = -1

        while pkt_length < 0 or len(self._readbuf) < pkt_length + 4:
            data = self._sd.recv(8192)
            if not len(data):
                break

            self._readbuf.extend(data)
            if len(self._readbuf) >= 4:
                pkt_length = struct.unpack("!L", self._readbuf[0:4])[0]

        if pkt_length < 0:
            return None

        data = self._readbuf[4:pkt_length + 4]
        del self._readbuf[:pkt_length + 4]
        return data

    def _connect(self):
        _, self._ctx = kerberos.authGSSClientInit(self._principal)
        challange = ""
        while True:
            rc = kerberos.authGSSClientStep(self._ctx, challange)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                break
            b64 = kerberos.authGSSClientResponse(self._ctx)
            encrypted = base64.b64decode(b64)
            self._sd.send(struct.pack("!L", len(encrypted)))
            self._sd.send(encrypted)
            encrypted = self._read_pkt()
            challange = base64.b64encode(encrypted)
        self._connected = True

    def close(self):
        self._sd.close()
        self._sd = self.__class__._closedsocket()
        if self._ctx:
            kerberos.authGSSClientClean(self._ctx)

    def send(self, data, flags=0):
        if flags:
            raise NotImplementedError

        if not self._connected:
            self._connect()

        b64 = base64.b64encode(data)
        kerberos.authGSSClientWrap(self._ctx, b64)
        b64 = kerberos.authGSSClientResponse(self._ctx)
        encrypted = base64.b64decode(b64)
        self._sd.send(struct.pack("!L", len(encrypted)))
        self._sd.send(encrypted)

    sendall = send

    def recv(self, bufsize, flags=0):
        if flags:
            raise NotImplementedError

        if not self._connected:
            self._connect()

        while len(self._decryptbuf) < bufsize:
            encrypted = self._read_pkt()
            if not len(encrypted):
                break
            b64 = base64.b64encode(encrypted)
            kerberos.authGSSClientUnwrap(self._ctx, b64)
            b64 = kerberos.authGSSClientResponse(self._ctx)
            self._decryptbuf.extend(base64.b64decode(b64))

        result = self._decryptbuf[:bufsize]
        del self._decryptbuf[:bufsize]
        return str(result)

    def makefile(self, mode='r', bufsize=-1):
        return socket._fileobject(self, mode, bufsize, close=True)

    def dup(self):
        raise NotImplementedError

    def sendto(self, *args):
        raise NotImplementedError

    def recvfrom(self, *args):
        raise NotImplementedError

    def recvfrom_into(self, *args):
        raise NotImplementedError

    def __getattr__(self, attr):
        # Proxy requests to the embedded socket
        return getattr(self._sd, attr)


class GSSHTTPConnection(ChunkedHTTPConnection):

    def __init__(self, host, port, service=None, strict=None):
        ChunkedHTTPConnection.__init__(self, host, port, strict)
        self.service = service

    def connect(self):
        ChunkedHTTPConnection.connect(self)
        try:
            self.sock = GSSSocket(self.sock, self.service + '@' + self.host)
            self.sock._connect()
        except kerberos.BasicAuthError as e:
            raise NotConnected(e)
