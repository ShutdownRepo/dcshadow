from R2Log import logger

from dcshadow.utils.MetaSingleton import MetaSingleton
from dcshadow.utils.client.LdapClient import LdapClient
from dcshadow.utils.client.DrsClient import DrsClient


class SessionsManager(metaclass=MetaSingleton):
    def __init__(self):
        self.__ldap_client = None
        self.__drs_client = None

    def initiate_ldap(self, domain: str, username: str, password: str, lm_hash: str, nt_hash: str, aes_key: str, kerberos: bool, dc_ip: str, use_ldaps: bool):
        self.__ldap_client = LdapClient(domain=domain, username=username, password=password, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, kerberos=kerberos, dc_ip=dc_ip, use_ldaps=use_ldaps)
        logger.debug(f"Obtained LDAP session: {self.__ldap_client.session}")

    def initiate_drs(self, domain: str, username: str, password: str, lm_hash: str, nt_hash: str, aes_key: str, dc_ip: str):
        self.__drs_client = DrsClient(domain=domain, username=username, password=password, lm_hash=lm_hash, nt_hash=nt_hash, aes_key=aes_key, dc_ip=dc_ip)
        logger.debug(f"Obtained DRS session: {self.__drs_client.session}")

    def get_ldap(self):
        if self.__ldap_client is None:
            raise ValueError("LDAP client has not been initialized yet!")
        return self.__ldap_client

    def get_drs(self):
        if self.__drs_client is None:
            raise ValueError("RPC client has not been initialized yet!")
        return self.__drs_client
