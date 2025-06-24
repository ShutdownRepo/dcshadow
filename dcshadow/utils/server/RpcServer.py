import os
import socketserver
from binascii import unhexlify, hexlify
from struct import pack

from R2Log import logger

from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCServer, MSRPCHeader, SEC_TRAILER, AUTH_TYPES, MSRPC_BINDACK, CtxItemResult, \
    MSRPCBindAck, MSRPCBind, CtxItem, MSRPC_CONT_RESULT_ACCEPT, msrpc_message_type, MSRPC_BIND, MSRPC_ALTERCTX, \
    MSRPC_REQUEST, MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_TYPE, RPC_C_AUTHN_GSS_KERBEROS, MSRPC_CONT_RESULT_USER_REJECT, \
    MSRPC_ALTERCTX_R, MSRPCRequestHeader, MSRPCRespHeader, MSRPC_BINDNAK, MSRPC_FAULT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.krb5 import gssapi, crypto, constants
from impacket.krb5.asn1 import AP_REQ, EncTicketPart, Authenticator, AP_REP, EncAPRepPart
from impacket.krb5.constants import KerberosMessageTypes
from impacket.krb5.crypto import Key, _enctype_table
from impacket.uuid import uuidtup_to_bin, bin_to_uuidtup
from pyasn1.codec.der import decoder, encoder

NDRSyntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


class RPCServer(socketserver.ThreadingMixIn, socketserver.TCPServer):  # based on https://github.com/fortra/impacket/pull/1299
    def __init__(self, server_address, handler_class, drs_port: int = None):
        socketserver.TCPServer.allow_reuse_address = True
        self.drs_port = drs_port
        socketserver.TCPServer.__init__(self, server_address, handler_class)

    # TODO setListenPort to avoid race condition with getListenPort and threads ?

    def getListenPort(self):
        return self.socket.getsockname()[1]


class RPCServerHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.client = None
        self.target = None
        self.auth_user = None
        self.transport = None
        self.request_header = None
        self.request_pdu_data = None
        self.request_sec_trailer = None
        self.request_auth_type = None
        self.encryption_key_type = None
        self.encryption_key = None
        self.cipher = None
        self.sequence_number = None
        self.server = server  # This is ugly, any other -more elegant- way?
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        self.transport = DCERPCServer(self.request)
        logger.debug(f"RPC: Received connection from {self.client_address[0]}")

    def handle(self):
        try:
            while True:
                data = self.transport.recv()
                if data is None:
                    logger.debug('RPC: Connection closed by client')
                    return
                response = self.handle_message_type(data)
                if response:
                    logger.debug('RPC: Sending packet of type %s' % msrpc_message_type[response['type']])
                    self.transport.send(response)
        except KeyboardInterrupt:
            raise
        except ConnectionResetError:
            logger.error("Connection reset.")
        except Exception as e:
            logger.debug("Exception:", exc_info=True)
            logger.error('Exception in RPC request handler: %s' % e)

    def handle_message_type(self, data):  # we need to re-do all of this by taking inspiration from rpcrt.py, which
        self.request_header = MSRPCHeader(data)
        if self.request_header['auth_len'] > 0:
            self.request_sec_trailer = SEC_TRAILER(self.request_header['sec_trailer'])
            for _auth_type in AUTH_TYPES:
                if self.request_sec_trailer['auth_type'] == _auth_type.value:
                    self.request_auth_type = _auth_type
        _auth_message = f"with {self.request_auth_type.name} authentication" if self.request_sec_trailer else "without authentication"
        logger.debug(f"RPC: Received {msrpc_message_type[self.request_header['type']]} packet {_auth_message}")
        if self.request_header['type'] == MSRPC_BIND:
            return self.handle_rpc_bind(rpc_payload=data)
        elif self.request_header['type'] == MSRPC_ALTERCTX:
            return self.handle_rpc_alterctx(rpc_payload=data)
        elif self.request_header['type'] == MSRPC_REQUEST:
            return self.handle_rpc_request(rpc_payload=data)
        else:
            logger.error('RPC: Packet type received not supported: %a' % msrpc_message_type[self.request_header['type']])
            return self.send_error(MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_TYPE)

    def handle_rpc_bind(self, rpc_payload):
        if self.request_sec_trailer:
            if self.request_auth_type.value == RPC_C_AUTHN_GSS_KERBEROS:
                # ap_req = decoder.decode(self.request_header['auth_data'], asn1Spec=AP_REQ())[0]
                # if ap_req['authenticator']['etype'] == 23:
                #     response = MSRPCBindNak()
                #     # response['RejectedReason'] = b''
                #     # response['SupportedVersions'] = b''
                #     logger.debug('Answering to a BIND with Kerberos authentication. Rejecting because of RC4')
                #     return response
                self.request_pdu_data = MSRPCBind(self.request_header['pduData'])
                response = MSRPCBindAck()
                replicated_attributes = ['ver_major', 'ver_minor', 'flags', 'representation', 'call_id']
                for attr in replicated_attributes:
                    response[attr] = self.request_header[attr]
                response['type'] = MSRPC_BINDACK
                # resp['auth_len'] = 0  # todo can we, and must we set this?
                response['max_tfrag'] = self.request_pdu_data['max_tfrag']
                response['max_rfrag'] = self.request_pdu_data['max_rfrag']
                response['assoc_group'] = 0x1337  # must NOT be 0
                # CONTEXT (CTX)
                response['ctx_num'] = 0
                response['ctx_items'] = b''
                data = self.request_pdu_data['ctx_items']
                for i in range(self.request_pdu_data['ctx_num']):
                    itemResult = CtxItemResult()
                    item = CtxItem(data)
                    # removing item data to go to the next
                    data = data[len(item):]
                    # check if the item is 32bit NDR
                    if item['TransferSyntax'] == uuidtup_to_bin(NDRSyntax):
                        itemResult['TransferSyntax'] = uuidtup_to_bin(NDRSyntax)
                        # Now Check if the interface is what we listen
                        for listening_uuid in self.transport._listenUUIDS:
                            if item['AbstractSyntax'] == listening_uuid:
                                # Match, we accept the bind request
                                response['SecondaryAddr'] = self.transport._listenUUIDS[item['AbstractSyntax']]['SecondaryAddr']  # should be the port of the listening Endpoint
                                response['SecondaryAddrLen'] = len(response['SecondaryAddr']) + 1
                                self.transport._boundUUID = listening_uuid
                                itemResult['Reason'] = 0  # Abstract Syntax supported
                                itemResult['Result'] = MSRPC_CONT_RESULT_ACCEPT
                            else:
                                itemResult['Reason'] = 1  # Abstract Syntax not supported
                                itemResult['Result'] = MSRPC_CONT_RESULT_USER_REJECT
                                logger.error(
                                    'Bind request for an unsupported interface %s' % bin_to_uuidtup(
                                        item['AbstractSyntax']))
                    else:
                        itemResult['Reason'] = 2  # Transfer Syntax not supported
                        itemResult['Result'] = MSRPC_CONT_RESULT_USER_REJECT
                    response['ctx_items'] += itemResult.getData()
                    response['ctx_num'] += 1
                response['Pad'] = 'A' * ((4 - ((response["SecondaryAddrLen"] + MSRPCBindAck._SIZE) % 4)) % 4)
                response['sec_trailer'] = self.request_sec_trailer
                try:
                    response['auth_data'] = self.gss_kerberos_ap_req()  # todo need to have an if ap_req, then build ap_rep, to make sure we don't build ap_rep when not asked to. For example, alterctx_r relies on this and unsets auth-data and sec-trailer, we need to find a better way to do this.
                except:
                    logger.debug("Couldn't decode auth data as AP-REQ, probably not an AP-REQ")  # todo we NEED to be able to tell the difference and act accordingly, and have a wider kerberos packet handler
                response['frag_len'] = len(response.getData())
                logger.debug('Answering to a BIND with Kerberos authentication')
                return response
            else:
                raise Exception(f'RPC: Auth type received not supported: {self.request_auth_type.name}')
        else:
            logger.debug('RPC: Answering to a BIND without authentication')
            return self.transport.processRequest(rpc_payload)

    def handle_rpc_alterctx(self, rpc_payload):
        if self.request_sec_trailer:
            if self.request_auth_type.value == RPC_C_AUTHN_GSS_KERBEROS:
                self.request_pdu_data = MSRPCBind(self.request_header['pduData'])
                response = self.handle_rpc_bind(rpc_payload=rpc_payload)
                response['type'] = MSRPC_ALTERCTX_R
                response['sec_trailer'] = b''  # unsetting authentication-related data, because it works right now, but maybe it's best we answer with something? Don't know
                response['auth_data'] = b''  # unsetting authentication-related data, because it works right now, but maybe it's best we answer with something? Don't know
                response['frag_len'] = len(response.getData())
                logger.debug('Answering to a ALTERCTX with Kerberos authentication')
                return response
            else:
                raise Exception(f'RPC: Auth type received not supported: {self.request_auth_type.name}')

    def handle_rpc_request(self, rpc_payload):
        if self.request_sec_trailer:
            if self.request_auth_type.value == RPC_C_AUTHN_GSS_KERBEROS and self.request_sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                _request_header = MSRPCRequestHeader(rpc_payload)
                _encrypted_stub = _request_header['pduData']
                self.request_sec_trailer = SEC_TRAILER(_request_header['sec_trailer'])
                auth_data = _request_header['sec_trailer'] + _request_header['auth_data']
                gss = gssapi.GSSAPI(cipher=self.cipher)
                answer, cfounder = gss.GSS_Unwrap(
                    sessionKey=self.encryption_key,
                    data=_encrypted_stub,
                    sequenceNumber=self.sequence_number,
                    direction='accept',  # not init
                    authData=auth_data,
                    keyUsage=gssapi.KG_USAGE_INITIATOR_SEAL,
                    dce_rpc_header=_request_header.getData()[:len(MSRPCRequestHeader())],
                    auth_data_header=auth_data[:8]
                )
                # if self.request_sec_trailer['auth_pad_len']:
                #     answer = answer[:-self.request_sec_trailer['auth_pad_len']]
                _request_header['pduData'] = answer
                # if len(_request_header['pduData']) & 3 != 0:
                #     _request_header['pduData'] = crypto._zeropad(_request_header['pduData'], 4)
                _request_header['frag_len'] = len(_request_header.get_packet())
                # _request_header['auth_len'] = 0
                # _request_header['auth_dataLen'] = 0
                # _request_header['dataLen'] = len(_request_header['pduData'])
                # _request_header['sec_trailer'] = b''
                # _request_header['auth_data'] = b''
                # _request_header['frag_len'] = len(MSRPCRequestHeader())+len(_request_header['pduData'])+_request_header['_pad']
                response = self.transport.processRequest(_request_header.getData())

                # Impacket defines some of those when sending, but we want to define the right structure before since it will be part of the blob that is hashed for integrity
                # Also, it would be cleaner to define those in rpcrt.processRequest() but it could potentially impact many other things... keeping it here atm
                response['alloc_hint'] = len(response['pduData'])
                # response['sec_trailer']['auth_pad_len'] = response['alloc_hint'] % 16
                # response['pduData'] = response['pduData'].getData() + b'\x00' * response['sec_trailer']['auth_pad_len']
                padded_pdudata = crypto._zeropad(response['pduData'].getData(),16)
                response['sec_trailer'] = SEC_TRAILER(response['sec_trailer'])
                response['sec_trailer']['auth_pad_len'] = len(padded_pdudata)-len(response['pduData'])
                response['pduData'] = padded_pdudata
                # response['sec_trailer']['auth_pad_len'] = (16 - (response['alloc_hint'] % 16)) % 16
                # response['pduData'] = response['pduData'].getData() + b'\x00' * response['sec_trailer']['auth_pad_len']
                response['auth_len'] = len(gss.get_filler(response['pduData'])) + len(cfounder) + len(gss.WRAP()) + self.cipher.macsize + len(gss.WRAP())
                response['frag_len'] = len(response.get_packet())
                sealedMessage, signature = gss.GSS_Wrap(
                    sessionKey=self.encryption_key,
                    data=response['pduData'],
                    direction='accept', # not init
                    encrypt=True,  # Sealing
                    acceptorSubkey=False,  # using subkey from ap-req
                    sequenceNumber=self.sequence_number,
                    keyUsage=gssapi.KG_USAGE_ACCEPTOR_SEAL,
                    dce_rpc_header=MSRPCRespHeader(response.getData()).getData()[:len(MSRPCRespHeader())],  # FIXME This can be done better and cleaner imo
                    auth_data_header=response['sec_trailer'].getData()
                )
                response['pduData'] = sealedMessage
                response['auth_data'] = signature
                response['frag_len'] = len(response.get_packet())
                self.sequence_number += 1
                return response
            else:
                raise Exception(f'RPC: Auth type received not supported: {self.request_auth_type.name}')
        else:
            logger.debug('RPC: Answering to a REQUEST without authentication')
            return self.transport.processRequest(rpc_payload)
        pass


    def gss_kerberos_ap_req(self):
        class KeyUsageNumbers(Enum):  # RFC 4120 - 7.5.1. Key Usage Numbers
            # TODO add values and refer when using newCipher.enc/decrypt(key, KEYUSAGE, data)
            pass

        krb_blob = self.request_header['auth_data']
        # TODO handle if not ap_rep, raise NotImplem
        ap_req = decoder.decode(krb_blob, asn1Spec=AP_REQ())[0]
        # TODO calculate the keys dynamically
        # _rc4 = "11baff16dfa02faa432a18b47866fe22"
        # _aes256 = "9192245209f61d54381cc45a76545d6e781445fad34f92e942a364c7a919f3f4"
        # _aes128 = "5ea518c068a57ec97956af47269d4973"
        # keys = {
        #     23: unhexlify("11baff16dfa02faa432a18b47866fe22"),
        #     18: unhexlify("9192245209f61d54381cc45a76545d6e781445fad34f92e942a364c7a919f3f4"),
        #     17: unhexlify("5ea518c068a57ec97956af47269d4973"),
        # }
        _rc4 = os.environ["RC4"]
        _aes256 = os.environ["AES256"]
        _aes128 = os.environ["AES128"]
        keys = {
            23: unhexlify(_rc4),
            18: unhexlify(_aes256),
            17: unhexlify(_aes128),
        }
        ekeys = {}
        for kt, key in keys.items():
            ekeys[kt] = Key(kt, key)
        etype = ap_req['authenticator']['etype']
        logger.debug('Ticket is encrypted with %s (etype %d)' % (constants.EncryptionTypes(etype).name, etype))
        key = ekeys[etype]
        logger.debug('Using corresponding key: %s' % hexlify(key.contents).decode('utf-8'))
        encTicket = ap_req['ticket']['enc-part']['cipher']
        self.cipher = _enctype_table[int(etype)]
        plainTextTicket, _ = self.cipher.decrypt(key, 2, encTicket)
        logger.debug('Ticket successfully decrypted')
        # TODO print the cname & crealm etc. of the domain controller account loggerger in, interesting info
        encTicketPart = decoder.decode(plainTextTicket, asn1Spec=EncTicketPart())[0]
        sessionKey = Key(encTicketPart['key']['keytype'], bytes(encTicketPart['key']['keyvalue']))
        logger.debug("Using session key to decrypt authenticator: %s" % hexlify(sessionKey.contents).decode('utf-8'))
        encApReqAuthenticator, _ = self.cipher.decrypt(sessionKey, 11, ap_req['authenticator']['cipher'])
        logger.debug('Authenticator successfully decrypted')
        ApRepAuthenticator = decoder.decode(encApReqAuthenticator, asn1Spec=Authenticator())[0]
        self.encryption_key_type = ApRepAuthenticator['subkey']['keytype']
        # self.encryption_key = Key(self.encryption_key_type,b"\xa9\x14\xcb\x0d\xa0\x3d\xcc\x32\x13\x49\xba\x8d\xe1\x07\xe4\xda" \
# b"\xf8\xf8\x1f\x10\xdc\xd7\xf7\x5a\x82\x06\x45\x5a\x1e\x6c\xbe\xde")
        self.encryption_key = Key(self.encryption_key_type, ApRepAuthenticator['subkey']['keyvalue'].asOctets())
        # self.encryption_key = Key(self.encryption_key_type, sessionKey.contents)
        ap_rep = AP_REP()
        ap_rep['pvno'] = 5
        ap_rep['msg-type'] = KerberosMessageTypes.KRB_AP_REP.value
        ap_rep['enc-part']['etype'] = ap_req['authenticator']['etype']
        encAPRep = EncAPRepPart()
        encAPRep['ctime'] = ApRepAuthenticator['ctime'].prettyPrint()
        encAPRep['cusec'] = ApRepAuthenticator['cusec'].prettyPrint()
        # sending randomly generated key
        encAPRep['subkey']['keyvalue'] = self.encryption_key.contents
        encAPRep['subkey']['keytype'] = self.encryption_key_type
        encAPRep['seq-number'] = ApRepAuthenticator['seq-number'].prettyPrint()
        self.sequence_number = int(ApRepAuthenticator['seq-number'])
        # self.sequence_number = int.from_bytes(os.urandom(4))
        # self.sequence_number = 1336131338
        # encAPRep['seq-number'] = self.sequence_number
        encEncApRep = encoder.encode(encAPRep)
        encApRepCipher = self.cipher.encrypt(sessionKey, 12, encEncApRep, None)
        ap_rep['enc-part']['cipher'] = encApRepCipher
        return encoder.encode(ap_rep)

    def send_error(self, status):
        packet = MSRPCRespHeader(self.request_header.getData())
        request_type = self.request_header['type']
        if request_type == MSRPC_BIND:
            packet['type'] = MSRPC_BINDNAK
        else:
            packet['type'] = MSRPC_FAULT
        if status:
            packet['pduData'] = pack('<L', status)
        return packet

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        logger.debug(f"RPC: Closing down connection {self.client_address[0]}")
        return socketserver.BaseRequestHandler.finish(self)
