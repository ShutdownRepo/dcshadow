import ssl
from binascii import unhexlify
from typing import Any

import ldap3
from R2Log import logger

from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech


def get_machine_name(dc_ip: str, domain: str):
    if dc_ip is not None:
        s = SMBConnection(dc_ip, dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def init_ldap_connection(target: Any, tls_version: Any, kerberos: bool, domain: str, username: str, password: str, lm_hash: str, nt_hash: str, aes_key: str, dc_ip: str):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(connection=ldap_session, target=target, username=username, password=password, domain=domain, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, kdc_host=dc_ip)
    elif not (lm_hash == '' and nt_hash == ''):
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lm_hash + ":" + nt_hash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def ldap3_kerberos_login(connection: ldap3.Connection, target: str, username: str, password: str, domain='', lm_hash='', nt_hash='', aes_key='', kdc_host=None, tgt=None, st=None, use_cache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lm_hash != '' or nt_hash != '':
        if len(lm_hash) % 2:
            lm_hash = '0' + lm_hash
        if len(nt_hash) % 2:
            nt_hash = '0' + nt_hash
        try:  # just in case they were converted already
            lm_hash = unhexlify(lm_hash)
            nt_hash = unhexlify(nt_hash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if tgt is not None or st is not None:
        use_cache = False

    target = 'ldap/%s' % target
    if use_cache:
        domain, username, tgt, st = CCache.parseFile(domain, username, target)

    # First of all, we need to get a TGT for the user
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if tgt is None:
        if st is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lm_hash, nt_hash, aes_key, kdc_host)
    else:
        tgt = tgt['KDC_REP']
        cipher = tgt['cipher']
        sessionKey = tgt['sessionKey']

    if st is None:
        serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdc_host, tgt, cipher, sessionKey)
    else:
        tgs = st['KDC_REP']
        cipher = st['cipher']
        sessionKey = st['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, username, None, 'GSS-SPNEGO', blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


class LdapClient:
    server = None
    session = None

    def __init__(self, domain: str, username: str, password: str, lm_hash: str, nt_hash: str, aes_key: str, kerberos: bool, dc_ip: str, use_ldaps: bool):
        if kerberos:
            target = get_machine_name(dc_ip=dc_ip, domain=domain)
        else:
            if dc_ip is not None:
                target = dc_ip
            else:
                target = domain

        if use_ldaps is True:
            try:
                self.server, self.session = init_ldap_connection(target=target, tls_version=ssl.PROTOCOL_TLSv1_2, domain=domain, username=username, password=password, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, dc_ip=dc_ip, kerberos=kerberos)
            except ldap3.core.exceptions.LDAPSocketOpenError:
                self.server, self.session = init_ldap_connection(target=target, tls_version=ssl.PROTOCOL_TLSv1, domain=domain, username=username, password=password, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, dc_ip=dc_ip, kerberos=kerberos)
        else:
            self.server, self.session = init_ldap_connection(target=target, tls_version=None, domain=domain, username=username, password=password, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, dc_ip=dc_ip, kerberos=kerberos)

    def check_ldap_result(self):
        if self.session.result['result'] == 0:
            return True
        else:
            if self.session.result['result'] == 50:
                logger.error('Could not modify object, the server reports insufficient rights: %s', self.session.result['message'])
            elif self.session.result['result'] == 19:
                logger.error('Could not modify object, the server reports a constrained violation: %s', self.session.result['message'])
            else:
                logger.error('The server returned an error: %s', self.session.result['message'])
            return False