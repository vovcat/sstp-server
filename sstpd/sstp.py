import os, struct, logging, asyncio, socket, ssl
import subprocess, tempfile, hmac, hashlib
from enum import Enum
from asyncio import Protocol
from functools import partial

from . import __version__
from .constants import *
from .packets import SSTPDataPacket, SSTPControlPacket
from .utils import hexdump
from .ppp import PPPDProtocol, PPPDProtocolFactory, is_ppp_control_frame, PPPDSSTPPluginFactory
from .proxy_protocol import parse_pp_header, PPException, PPNoEnoughData


HTTP_REQUEST_BUFFER_SIZE = 10 * 1024
HELLO_TIMEOUT = 60


class State(Enum):
    SERVER_CALL_DISCONNECTED = 'Server_Call_Disconnected'
    SERVER_CONNECT_REQUEST_PENDING = 'Server_Connect_Request_Pending'
    SERVER_CALL_CONNECTED_PENDING = 'Server_Call_Connected_Pending'
    SERVER_CALL_CONNECTED = 'Server_Call_Connected'
    CALL_DISCONNECT_IN_PROGRESS_1 = 'Call_Disconnect_In_Progress_1'
    CALL_DISCONNECT_IN_PROGRESS_2 = 'Call_Disconnect_In_Progress_2'
    CALL_DISCONNECT_TIMEOUT_PENDING = 'Call_Disconnect_Timeout_Pending'
    CALL_DISCONNECT_ACK_PENDING = 'Call_Disconnect_Timeout_Pending'
    CALL_ABORT_IN_PROGRESS_1 = 'Call_Abort_In_Progress_1'
    CALL_ABORT_IN_PROGRESS_2 = 'Call_Abort_In_Progress_2'
    CALL_ABORT_TIMEOUT_PENDING = 'Call_Abort_Timeout_Pending'
    CALL_ABORT_PENDING = 'Call_Abort_Timeout_Pending'


def sstp_length(s):
    return ((s[0] & 0x0f) << 8) + s[1]  # Ignore R


class SSTPProtocol(Protocol):

    def __init__(self, logging):
        self.logging = logging
        self.loop = asyncio.get_event_loop()
        self.state = State.SERVER_CALL_DISCONNECTED
        self.sstp_packet_len = 0
        self.receive_buf = bytearray()
        self.nonce = None
        self.pppd = None
        self.retry_counter = 0
        self.hello_timer = None
        self.reset_hello_timer()
        self.proxy_protocol_passed = False
        self.correlation_id = None
        self.ssl = False
        self.remote_host = None
        self.remote_port = None
        # PPP SSTP API
        self.ppp_sstp = None
        # High(er) LAyer Key (HLAK)
        self.hlak = None
        # Client Compound MAC
        self.client_cmac = None

    def init_logging(self):
        self.logging = SSTPLogging(self.logging, {
            'id': self.correlation_id,
            'host': self.remote_host,
            'port': self.remote_port,
        })

    def connection_made(self, transport):
        self.transport = transport
        self.proxy_protocol_passed = not self.factory.proxy_protocol

        peer = self.transport.get_extra_info("peername")
        if hasattr(peer, 'host'):
            self.remote_host = str(peer.host)
            self.remote_port = int(peer.port) if hasattr(peer, 'port') else None
        elif type(peer) == tuple:
            self.remote_host = peer[0]
            self.remote_port = peer[1]

        self.loop.create_task(self.connection_made_detect())

    async def connection_made_detect(self):
        self.transport.pause_reading()
        del self.loop._transports[self.transport._sock_fd]
        self.loop.add_reader(self.transport._sock_fd, self.connection_made_read)

    def connection_made_read(self):
        self.loop.remove_reader(self.transport._sock_fd)
        self.loop._transports[self.transport._sock_fd] = self.transport
        self.transport.resume_reading()
        ssl = False
        try:
            data = self.transport._sock.recv(1, socket.MSG_PEEK)
            if len(data) and data[0] in (22, 128):
                self.loop.create_task(self.connection_made_is_ssl())
                ssl = True
        except ConnectionResetError:
            data = None
        self.logging.info(f'Connection from {self.remote_host}:{self.remote_port} data={data!r} ssl={bool(ssl)}')

    async def connection_made_is_ssl(self):
        try:
            transport = await self.loop.start_tls(self.transport, self, self.factory.ssl_ctx, server_side=True)
            self.transport = transport
            self.ssl = True
        except (ConnectionResetError, ssl.SSLError) as e:
            # ssl.SSLError: [SSL: VERSION_TOO_LOW]
            # ssl.SSLError: [SSL: NO_SUITABLE_SIGNATURE_ALGORITHM]
            self.logging.info('Connection error %s', e)

    def data_received(self, data):
        self.logging.debug(f'data_received {data[:12]!r}')
        if self.state == State.SERVER_CALL_DISCONNECTED:
            if self.proxy_protocol_passed:
                self.http_data_received(data)
            else:
                self.proxy_protocol_data_received(data)
        else:
            self.sstp_data_received(data)

    def connection_lost(self, reason):
        self.logging.info('Connection finished.')
        if self.pppd is not None and self.pppd.transport is not None:
            try:
                self.pppd.transport.terminate()
            except ProcessLookupError:
                self.logging.warning('PPP process is gone already')
                pass
            except Exception as e:
                self.logging.warning('Unexpected exception %s', str(e))
                pass
            if self.factory.remote_pool is not None:
                self.factory.remote_pool.unregister(self.pppd.remote)
                self.logging.info('Unregistered address %s', self.pppd.remote);
        self.hello_timer.cancel()
        self.ppp_sstp_api_close()

    def proxy_protocol_data_received(self, data):
        self.receive_buf.extend(data)
        try:
            src, dest, self.receive_buf = parse_pp_header(self.receive_buf)
        except PPNoEnoughData:
            pass
        except PPException as e:
            self.logging.warning('PROXY PROTOCOL parsing error: %s', str(e))
            self.transport.close()
        else:
            self.logging.debug('PROXY PROTOCOL header parsed: src %s, dest %s', src, dest)
            self.remote_host = src[0]
            self.proxy_protocol_passed = True
            if self.receive_buf:
                self.data_received(b'')

    def http_data_received(self, data):
        def http_close(err, *args):
            logging.warning(err, *args)
            self.transport.write(b'HTTP/1.1 400 Bad Request\r\n'
                b'Server: SSTP-Server/%s\r\n\r\n%s\r\n' % (
                str(__version__).encode(), (err % args).encode()))
            self.transport.close()

        self.receive_buf.extend(data)
        if b'\r\n\r\n' not in self.receive_buf:
            if len(self.receive_buf) > HTTP_REQUEST_BUFFER_SIZE:
                http_close('Request is too large, may not be a valid HTTP request.')
            return

        headers = self.receive_buf.split(b'\r\n')
        self.receive_buf.clear()

        try:
            request_line = headers[0].decode(errors='replace')
            self.logging.debug('%s', request_line)
            method, uri, version = request_line.split()
        except ValueError:
            return http_close('Not a valid HTTP request: %r', request_line)

        hdict = {}
        for h in headers[1:]:
            if not h: break
            line = h.decode(errors='replace')
            try: k, v = line.split(':', 1)
            except ValueError: continue
            hdict[k.lower()] = v.strip()
            self.logging.debug('%s', line)

        '''
        CGET -X SSTP_DUPLEX_POST -H SSTPCORRELATIONID:test http://sstp.frik.su/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ -d test

        SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1
        SSTPCORRELATIONID: {C129D75C-4301-000E-DB3E-2AC10143DB01}
        Content-Length: 18446744073709551615
        Host: sstp.host.name

        SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1
        Content-Length: 18446744073709551615
        Host: sstp.host.name
        SSTPCORRELATIONID: {4d56031f-c06f-4665-8615-fa080c6a35ba}

        #print(f'=== {self.loop._selector._fd_to_key.keys()} {[k for k in self.loop._transports.keys()]}')
        #print(f'=== {[h._callback for h in self.loop._ready]}')
        '''

        if method != 'SSTP_DUPLEX_POST' or version != 'HTTP/1.1':
            return http_close('Unexpected HTTP method (%s) and/or version (%s).', method, version)

        try: return http_close('Invalid Content-Type: %s', hdict['content-type'])
        except: pass

        try: self.correlation_id = hdict['sstpcorrelationid'].strip('{}')
        except: return http_close('Invalid correlation id')

        try: self.content_length = int(hdict['content-length'])
        except: return http_close('Invalid Content-Length')

        if self.content_length < 18446744073709551615:
            return http_close('Invalid Content-Length')

        # Use X-Forwarded-For and X-Forwarded-SourcePort headers over plain HTTP
        if not self.factory.proxy_protocol and (self.factory.no_ssl or not self.ssl):
            try: host = hdict['x-forwarded-for'].split(',')[0].strip()
            except: host = None
            try: port = int(hdict['x-forwarded-sourceport'].split(',')[0].strip())
            except: port = None
            if host: self.remote_host = host
            if host and port: self.remote_port = port # port can be None if not forwarded

        self.init_logging()
        self.logging.info(f'New client connection')

        self.transport.write(
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Length: 18446744073709551615\r\n'
            b'Server: SSTP-Server/%s\r\n\r\n' % str(__version__).encode())
        self.state = State.SERVER_CONNECT_REQUEST_PENDING

    def sstp_data_received(self, data):
        self.reset_hello_timer()
        self.receive_buf.extend(data)
        while len(self.receive_buf) >= 4:
            # Check version.
            if self.receive_buf[0] != 0x10:
                self.logging.warn('Unsupported SSTP version.')
                self.transport.close()
                return
            # Get length if necessary.
            if not self.sstp_packet_len:
                self.sstp_packet_len = sstp_length(self.receive_buf[2:4])
            if len(self.receive_buf) < self.sstp_packet_len:
                return
            packet = memoryview(self.receive_buf)[:self.sstp_packet_len]
            self.receive_buf = self.receive_buf[self.sstp_packet_len:]
            self.sstp_packet_len = 0
            self.sstp_packet_received(packet)

    def sstp_packet_received(self, packet):
        c = packet[1] & 0x01
        if c == 0:  # Data packet
            self.sstp_data_packet_received(packet[4:])
        else:  # Control packet
            msg_type = packet[4:6].tobytes()
            num_attrs = struct.unpack('!H', packet[6:8])[0]
            attributes = []
            attrs = packet[8:]
            while len(attributes) < num_attrs:
                id = attrs[1:2]
                length = sstp_length(attrs[2:4])
                value = attrs[4:length]
                attrs = attrs[length:]
                attributes.append((id, value))
            self.sstp_control_packet_received(msg_type, attributes)

    def sstp_data_packet_received(self, data):
        if __debug__:
            self.logging.debug('sstp => pppd (%s bytes).', len(data))
            self.logging.log(VERBOSE, hexdump(data))
        if self.pppd is None:
            print('pppd is None.')
            return
        self.pppd.write_frame(data)

    def sstp_control_packet_received(self, msg_type, attributes):
        self.logging.info('SSTP control packet (%s) received.',
                     MsgType.str.get(msg_type, msg_type))
        if msg_type == MsgType.CALL_CONNECT_REQUEST:
            protocolId = attributes[0][1]
            self.sstp_call_connect_request_received(protocolId)
        elif msg_type == MsgType.CALL_CONNECTED:
            attr = attributes[0][1]
            attr_obj = next(
                (a for a in attributes if a[0] == SSTP_ATTRIB_CRYPTO_BINDING),
                None
            )
            if attr_obj is None:
                self.logging.warn('Crypto Binding Attribute expected in Call Connect')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            attr = attr_obj[1]
            if len(attr) != 0x64:
                # MS-SSTP : 2.2.7 Crypto Binding Attribute
                self.logging.warn('Crypto Binding Attribute length MUST be 104 (0x068)')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            hash_type = attr[3]
            nonce = attr[4:36]
            if hash_type == CERT_HASH_PROTOCOL_SHA1:
                # strip and ignore padding
                cert_hash = attr[36:56]
                mac_hash = attr[68:88]
            elif hash_type == CERT_HASH_PROTOCOL_SHA256:
                cert_hash = attr[36:68]
                mac_hash = attr[68:100]
            else:
                self.logging.warn('Unsupported hash protocol in Crypto '
                    'Binding Attribute.')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            self.sstp_call_connected_received(hash_type, nonce,
                                              cert_hash, mac_hash)
        elif msg_type == MsgType.CALL_ABORT:
            if attributes:
                self.sstp_msg_call_abort(attributes[0][1])
            else:
                self.sstp_msg_call_abort()
        elif msg_type == MsgType.CALL_DISCONNECT:
            if attributes:
                self.sstp_msg_call_disconnect(attributes[0][1])
            else:
                self.sstp_msg_call_disconnect()
        elif msg_type == MsgType.CALL_DISCONNECT_ACK:
            self.sstp_msg_call_disconnect_ack()
        elif msg_type == MsgType.ECHO_REQUEST:
            self.sstp_msg_echo_request()
        elif msg_type == MsgType.ECHO_RESPONSE:
            self.sstp_msg_echo_response()
        else:
            self.logging.warn('Unknown type of SSTP control packet.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)

    def sstp_call_connect_request_received(self, protocolId):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != State.SERVER_CONNECT_REQUEST_PENDING:
            self.logging.warn('Not in the state.')
            self.transport.close()
            return
        if protocolId != SSTP_ENCAPSULATED_PROTOCOL_PPP:
            self.logging.warn('Unsupported encapsulated protocol.')
            nak = SSTPControlPacket(MsgType.CALL_CONNECT_NAK)
            nak.attributes = [(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
                    ATTRIB_STATUS_VALUE_NOT_SUPPORTED)]
            self.add_retry_counter_or_abort()
            return
        self.nonce = os.urandom(32)
        ack = SSTPControlPacket(MsgType.CALL_CONNECT_ACK)
        # hash protocol bitmask
        hpb = 0
        if len(self.factory.cert_hash.sha1) > 0:
            hpb |= CERT_HASH_PROTOCOL_SHA1
        if len(self.factory.cert_hash.sha256) > 0:
            hpb |= CERT_HASH_PROTOCOL_SHA256
        # 3 bytes reserved + 1 byte hash bitmap + nonce.
        ack.attributes = [(SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                b'\x00\x00\x00' + bytes([hpb]) + self.nonce)]
        ack.write_to(self.transport.write)

        args = ['115200', 'notty', 'file', self.factory.pppd_config_file]

        remote = ''
        if self.factory.remote_pool:
            remote = self.factory.remote_pool.apply()
            if remote is None:
                self.logging.warn('IP address pool is full. Cannot accept new connection.')
                self.abort()
                return

            if self.factory.ifname_prefix:
                ifname = self.factory.ifname_prefix + \
                    str(self.factory.remote_pool.addr_num(remote))
                args += ['ifname', ifname]

            self.logging.info('Registered address %s ifname %r', remote, ifname);

        args += ['%s:%s' % (self.factory.local, remote)]

        if self.factory.pppd_sstp_api_plugin is not None:
            # create a unique socket filename
            ppp_sock = tempfile.NamedTemporaryFile(prefix='ppp-sstp-api-', suffix='.sock')
            args += ['plugin', self.factory.pppd_sstp_api_plugin, 'sstp-sock', ppp_sock.name]
            ppp_event = self.loop.create_unix_server(
                    PPPDSSTPPluginFactory(callback=self),
                    path=ppp_sock.name)
            ppp_sock.close()
            task = asyncio.create_task(ppp_event)
            task.add_done_callback(self.ppp_sstp_api)

        sstp_env = {}
        if self.remote_host is not None:
            args += ['remotenumber', self.remote_host]
            args += ['set', 'REMOTE_HOST=' + self.remote_host]
            sstp_env['SSTP_REMOTE_HOST'] = self.remote_host
        if self.remote_port is not None:
            args += ['set', 'REMOTE_PORT=' + str(self.remote_port)]
            sstp_env['SSTP_REMOTE_PORT'] = str(self.remote_port)
        if self.correlation_id is not None:
            args += ['set', 'REMOTE_ID=' + self.correlation_id]
            sstp_env['SSTP_REMOTE_ID'] = self.correlation_id

        ppp_env = os.environ.copy()
        ppp_env.update(sstp_env)

        factory = PPPDProtocolFactory(callback=self, remote=remote)
        self.logging.info(f'subprocess_exec(factory, pppd={self.factory.pppd}, args={args}, env={sstp_env})')
        coro = self.loop.subprocess_exec(factory, self.factory.pppd, *args, env=ppp_env)
        task = asyncio.ensure_future(coro)
        task.add_done_callback(self.pppd_started)
        self.state = State.SERVER_CALL_CONNECTED_PENDING

    def pppd_started(self, task):
        self.logging.info('pppd started')
        err = task.exception()
        if err is not None:
            self.logging.warning("Fail to start pppd: %s", err)
            self.abort()
            return
        transport, protocol = task.result()
        self.pppd = protocol
        self.pppd.resume_producing()

    def ppp_sstp_api(self, task):
        err = task.exception()
        if err is not None:
            self.logging.warning("Fail to start PPP SSTP API: %s", err)
            self.abort()
            return
        server = task.result()
        self.ppp_sstp = server

    def ppp_sstp_api_close(self):
        if self.ppp_sstp is not None:
            socks = list(map(lambda s: s.getsockname(), self.ppp_sstp.sockets))

            self.logging.debug("Close PPP SSTP API.")
            self.ppp_sstp.close()

            for sock in socks:
                try:
                    self.logging.debug("Remove SSTP API sock %s", sock)
                    os.remove(sock)
                except:
                    pass

            self.ppp_sstp = None

    def sstp_call_connected_received(self, hash_type, nonce, cert_hash, mac_hash):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != State.SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
            return

        self.logging.debug("Received Cert %s: %s",
                ("SHA1", "SHA256")[hash_type == CERT_HASH_PROTOCOL_SHA256],
                cert_hash.hex())
        self.logging.debug("Received CMAC: %s", mac_hash.hex())

        if nonce != self.nonce:
            self.logging.error('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        if self.factory.cert_hash is not None \
                and cert_hash not in self.factory.cert_hash:
            self.logging.error("Certificate hash mismatch between server's "
                            "and client's. Reject this connection.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        if not self.should_verify_crypto_binding():
            self.logging.debug("No crypto binding needed.")
            self.state = State.SERVER_CALL_CONNECTED
            self.logging.info('Connection established.')
            return

        if self.hlak is None:
            self.logging.warning("Waiting for the Higher Layer Authentication "
                    "Key (HLAK) to verify Crypto Binding.")
            self.client_cmac = mac_hash
            return

        self.sstp_call_connected_crypto_binding(mac_hash)

    def sstp_call_connected_crypto_binding(self, mac_hash):
        if self.hlak is None:
            self.logging.error("Failed to verify Crypto Binding, as the "
                    "Higher Layer Authentication Key is missing.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        hash_type = (CERT_HASH_PROTOCOL_SHA1,
                CERT_HASH_PROTOCOL_SHA256)[len(mac_hash) == 32]

        # reconstruct Call Connect message with zeroed CMAC field
        cc_msg = bytes((0x10, 0x01, 0x00, 0x70))
        cc_msg += MsgType.CALL_CONNECTED
        # number of attributes + reserved
        cc_msg += bytes((0x00, 0x01, 0x00))
        cc_msg += SSTP_ATTRIB_CRYPTO_BINDING
        # attr length + reserved
        cc_msg += bytes((0x00, 0x68, 0x00, 0x00, 0x00))
        cc_msg += bytes([hash_type])
        cc_msg += self.nonce
        cc_msg += self.factory.cert_hash[hash_type == CERT_HASH_PROTOCOL_SHA256]
        # [padding + ] zeroed cmac [+ padding]
        cc_msg += bytes(0x70 - len(cc_msg))

        # Compound MAC Key (CMK) seed
        cmk_seed = b'SSTP inner method derived CMK'
        cmk_digest = (hashlib.sha1, hashlib.sha256)\
                [hash_type == CERT_HASH_PROTOCOL_SHA256]

        # [MS-SSTP] 3.2.5.{2,4} - If the higher-layer PPP authentication method
        # did not generate any keys, or if PPP authentication is bypassed, then
        # the HLAK MUST be 32 octets of 0x00
        for hlak in {self.hlak, bytes(32)}:
            # T1 = HMAC(HLAK, S | LEN | 0x01)
            t1 = hmac.new(hlak, digestmod=cmk_digest)

            # CMK len (length of digest) - 16-bits little endian
            cmk_len = bytes((t1.digest_size, 0))

            t1.update(cmk_seed)
            t1.update(cmk_len)
            t1.update(b'\x01')

            cmk = t1.digest()

            # CMAC = HMAC(CMK, CC_MSG)
            cmac = hmac.new(cmk, digestmod=cmk_digest)
            cmac.update(cc_msg)

            if hmac.compare_digest(cmac.digest(), mac_hash):
                break

        if __debug__:
            self.logging.debug("Crypto Binding CMK: %s", t1.hexdigest())
            self.logging.debug("Crypto Binding CMAC: %s", cmac.hexdigest())

        if not hmac.compare_digest(cmac.digest(), mac_hash):
            self.logging.error("Crypto Binding is invalid.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        self.logging.info("Crypto Binding is valid.")
        self.state = State.SERVER_CALL_CONNECTED
        self.logging.info('Connection established.')

    def sstp_msg_call_abort(self, status=None):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        self.logging.warn("Call abort.")
        if self.state == State.CALL_ABORT_PENDING:
            self.loop.call_later(1, self.transport.close)
            return
        self.state = State.CALL_ABORT_IN_PROGRESS_2
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(1, self.transport.close)

    def sstp_msg_call_disconnect(self, status=None):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        self.logging.info('Received call disconnect request.')
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_2
        ack = SSTPControlPacket(MsgType.CALL_DISCONNECT_ACK)
        ack.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_TIMEOUT_PENDING
        self.loop.call_later(1, self.transport.close)

    def sstp_msg_call_disconnect_ack(self):
        if self.state == State.CALL_DISCONNECT_ACK_PENDING:
            self.transport.close()
        elif self.state in (State.CALL_ABORT_PENDING,
                State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def sstp_msg_echo_request(self):
        self.logging.info('sstp_msg_echo_request')
        if self.state == State.SERVER_CALL_CONNECTED:
            response = SSTPControlPacket(MsgType.ECHO_RESPONSE)
            response.write_to(self.transport.write)
        elif self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def sstp_msg_echo_response(self):
        if self.state == State.SERVER_CALL_CONNECTED:
            self.reset_hello_timer()
        elif self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def hello_timer_expired(self, close):
        self.logging.debug('hello_timer_expired(close=%s)', close)
        if self.state == State.SERVER_CALL_DISCONNECTED:
            if hasattr(self, 'transport'): self.transport.close()  # TODO: follow HTTP
        elif close:
            self.logging.warn('Ping time out.')
            self.abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        else:
            self.logging.info('Send echo request.')
            echo = SSTPControlPacket(MsgType.ECHO_REQUEST)
            echo.write_to(self.transport.write)
            self.reset_hello_timer(True)

    def reset_hello_timer(self, close=False):
        if self.hello_timer is not None:
            self.hello_timer.cancel()
        self.hello_timer = self.loop.call_later(HELLO_TIMEOUT,
                partial(self.hello_timer_expired, close=close))

    def add_retry_counter_or_abort(self):
        self.retry_counter += 1
        if self.retry_counter > 3:
            self.abort(ATTRIB_STATUS_RETRY_COUNT_EXCEEDED)

    def abort(self, status=None):
        self.logging.warn('Abort (%s).', status)
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        if status is not None:
            msg.attributes = [(SSTP_ATTRIB_STATUS_INFO, status)]
        msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(3, self.transport.close)

    def write_ppp_frames(self, frames):
        if self.state == State.SERVER_CALL_CONNECTED_PENDING:
            frames = [f for f in frames if is_ppp_control_frame(f)]
        elif self.state != State.SERVER_CALL_CONNECTED:
            return
        for frame in frames:
            if __debug__:
                self.logging.debug('pppd => sstp (%d bytes)', len(frame))
                self.logging.log(VERBOSE, hexdump(frame))
            SSTPDataPacket(frame).write_to(self.transport.write)

    def ppp_stopped(self):
        if (self.state != State.SERVER_CONNECT_REQUEST_PENDING and
                self.state != State.SERVER_CALL_CONNECTED_PENDING and
                self.state != State.SERVER_CALL_CONNECTED):
            self.transport.close()
            return
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        msg.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_ACK_PENDING
        self.loop.call_later(3, self.transport.close)

    def higher_layer_authentication_key(self, send_key, recv_key):
        # [MS-SSTP] 3.2.5.2 - crypto binding - server mode
        hlak = recv_key + send_key
        # ensure hlak is 32 bytes long
        if len(hlak) < 32:
            hlak += bytes(32 - len(hlak))
        self.hlak = hlak[0:32]

        self.logging.info("Received Higher Layer Authentication Key.")
        self.logging.debug("Configured HLAK as %s", self.hlak.hex())

        self.ppp_sstp_api_close()

        if self.client_cmac is not None:
            self.sstp_call_connected_crypto_binding(self.client_cmac)

    def should_verify_crypto_binding(self):
        return (self.factory.pppd_sstp_api_plugin is not None)


class SSTPProtocolFactory:
    protocol = SSTPProtocol

    def __init__(self, config, remote_pool, cert_hash=None, ssl_ctx=None):
        self.pppd = config.pppd
        self.pppd_config_file = config.pppd_config
        self.ifname_prefix = config.ifname_prefix
        # detect ppp_sstp_api_plugin
        ppp_sstp_api_plugin = 'sstp-pppd-plugin.so'
        has_plugin = subprocess.run(
                [self.pppd, 'plugin', ppp_sstp_api_plugin, 'notty', 'dryrun'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pppd_sstp_api_plugin = (None, ppp_sstp_api_plugin)[has_plugin.returncode == 0]
        self.local = config.local
        self.proxy_protocol = config.proxy_protocol
        self.no_ssl = config.no_ssl
        self.remote_pool = remote_pool
        self.cert_hash = cert_hash
        self.ssl_ctx = ssl_ctx
        self.logging = logging.getLogger('SSTP')

    def __call__(self):
        proto = self.protocol(self.logging)
        proto.factory = self
        return proto


class SSTPLogging(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        if self.extra['host'] is None:
            return '[%s] %s' % (self.extra['id'], msg), kwargs
        elif self.extra['port'] is None:
            return '[%s/%s] %s' % (self.extra['id'], self.extra['host'], msg), kwargs
        else:
            return '[%s/%s:%d] %s' % (self.extra['id'], self.extra['host'], self.extra['port'], msg), kwargs
