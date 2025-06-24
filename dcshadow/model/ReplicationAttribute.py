import struct
from enum import Enum

from ldap3 import SUBTREE
from R2Log import logger
from typing import List, Dict, Union, Optional

from dcshadow.manager.SessionsManager import SessionsManager
from impacket.dcerpc.v5 import drsuapi


class ReplicationAttributeSerializer:
    # default entries from 5.16.4 ATTRTYP-to-OID Conversion
    __DEFAULT_ENTRIES = [
        {"index": 0, "string": b"\x55\x04"},  # OID: 2.5.4.6 (countryName attribute)
        {"index": 1, "string": b"\x55\x06"},  # OID: 2.5.6.2 (country class)
        {"index": 2, "string": b"\x2a\x86\x48\x86\xf7\x14\x01\x02"},  # OID: 1.2.840.113556.1.2.1 (instanceType attribute)
        {"index": 3, "string": b"\x2a\x86\x48\x86\xf7\x14\x01\x03"},  # OID: 1.2.840.113556.1.3.23 (container class)
        {"index": 4, "string": b"\x60\x86\x48\x01\x65\x02\x02\x01"},
        {"index": 5, "string": b"\x60\x86\x48\x01\x65\x02\x02\x03"},
        {"index": 6, "string": b"\x60\x86\x48\x01\x65\x02\x01\x05"},
        {"index": 7, "string": b"\x60\x86\x48\x01\x65\x02\x01\x04"},
        {"index": 8, "string": b"\x55\x05"},  # OID: 2.5.5.1 (attribute syntax: distinguished name)
        {"index": 9, "string": b"\x2a\x86\x48\x86\xf7\x14\x01\x04"},  # OID: 1.2.840.113556.1.4.1 (RDN attribute)
        {"index": 10, "string": b"\x2a\x86\x48\x86\xf7\x14\x01\x05"},  # OID: 1.2.840.113556.1.5.1 (securityObject class)
        {"index": 19, "string": b"\x09\x92\x26\x89\x93\xf2\x2c\x64"},
        {"index": 20, "string": b"\x60\x86\x48\x01\x86\xf8\x42\x03"},
        {"index": 21, "string": b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01"},
        {"index": 22, "string": b"\x60\x86\x48\x01\x86\xf8\x42\x03\x01"},
        {"index": 23, "string": b"\x2a\x86\x48\x86\xf7\x14\x01\x05\xb6\x58"},
        {"index": 24, "string": b"\x55\x15"},
        {"index": 25, "string": b"\x55\x12"},
        {"index": 26, "string": b"\x55\x14"},
        {"index": 27, "string": b"\x2b\x06\x01\x04\x01\x8b\x3a\x65\x77"}  # mimikatz includes this but not MS docs, do we need it ¯\_(ツ)_/¯
    ]

    __OID_PREFIX_TABLE = None

    def __init__(self, oid, value, serializer):
        self.value: List = value if isinstance(value, list) else [value]
        self.oid = oid
        self.serializer = serializer

    @classmethod
    def __init_prefix_table(cls):
        default_prefix_table = []
        for prefix in cls.__DEFAULT_ENTRIES:
            oid = drsuapi.OID_t()
            oid['length'] = len(prefix['string'])
            oid['elements'].extend(prefix['string'])
            prefix_entry = drsuapi.PrefixTableEntry()
            prefix_entry['ndx'] = prefix['index']
            prefix_entry['prefix'] = oid
            default_prefix_table.append(prefix_entry)

        return default_prefix_table

    @classmethod
    def get_prefix_table(cls):
        if cls.__OID_PREFIX_TABLE is None:
            cls.__OID_PREFIX_TABLE = cls.__init_prefix_table()
        return cls.__OID_PREFIX_TABLE

    def serialize(self):
        return self.serializer(self)

    def __baseSerializer(self, pVals: List[bytes], valLen: Optional[int] = None):
        attr = drsuapi.ATTR()
        attrid = drsuapi.MakeAttid(prefixTable=self.get_prefix_table(), oid=self.oid)
        attr['attrTyp'] = int.from_bytes(attrid.getData(), 'little')

        for pVal in pVals:
            attr_val = drsuapi.ATTRVAL()
            attr_val['valLen'] = len(pVal) if valLen is None else valLen
            attr_val['pVal'].extend(pVal)
            attr['AttrVal']['pAVal'].append(attr_val)

        attr['AttrVal']['valCount'] = len(attr['AttrVal']['pAVal'])
        return attr

    @staticmethod
    def __checkType(element, expected_type):
        if not isinstance(element, expected_type):
            raise TypeError(f"Data to serialize should be a {expected_type}, got: value={element}, type={type(element)}")

    def int32(self) -> drsuapi.ATTR:
        pVals = []
        for element in self.value:
            self.__checkType(element, int)
            pVals.append(struct.pack('<I', element))
        return self.__baseSerializer(pVals=pVals)

    def int64(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def attrtyp(self) -> drsuapi.ATTR:
        pVals = []
        for element in self.value:
            self.__checkType(element, str)
            TOFIX = drsuapi.MakeAttid(prefixTable=self.get_prefix_table(), oid=element).getData()
            HARDCODED = b"\x2f\x00\x17\x00"
            pVals.append(HARDCODED)  # FIXME don't use the hardcoded to match mimikatz, but fix MakeAttid or anything related
            # pVals.append(drsuapi.MakeAttid(prefixTable=self.get_prefix_table(), oid=element).getData())  # FIXME shouldn't prefixTable be NOT empty? self.get_prefix_table() ?
        return self.__baseSerializer(pVals=pVals)

    def octetString(self) -> drsuapi.ATTR:
        return self.__baseSerializer(pVals=self.value)

    def string8(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def string16(self) -> drsuapi.ATTR:
        pVals = []
        for element in self.value:
            self.__checkType(element, str)
            pVals.append(element.encode("utf-16-le"))
        return self.__baseSerializer(pVals=pVals)

    def securityDescriptor(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def sid(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def dsTime(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def syntaxAddress(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def syntaxDistnameBinary(self) -> drsuapi.ATTR:
        raise NotImplementedError

    def dsName(self) -> drsuapi.ATTR:
        pVals = []
        for element in self.value:
            if not isinstance(element, str):
                raise TypeError("Data to serialize should be a string")
            dsName = drsuapi.DSNAME_BINARY()
            dsName['SidLen'] = 0
            dsName['Sid'] = ''
            dsName['Guid'] = drsuapi.NULLGUID
            dsName['NameLen'] = len(element)
            dsName['StringName'] = (element + '\x00')
            dsName['structLen'] = len(dsName.getData())
            pVals.append(dsName.getData())
        return self.__baseSerializer(pVals=pVals)


class ReplicationAttribute:
    __VALUE_TYPE_MAP = {
        "2.5.5.8": ReplicationAttributeSerializer.int32,  # Boolean
        "2.5.5.9": ReplicationAttributeSerializer.int32,  # Enumeration, Integer
        "2.5.5.16": ReplicationAttributeSerializer.int64,  # LargeInteger
        "2.5.5.13": ReplicationAttributeSerializer.syntaxAddress,  # Object(Presentation-Address)
        "2.5.5.10": ReplicationAttributeSerializer.octetString,  # Object(Replica-Link), String(Octet)
        "2.5.5.5": ReplicationAttributeSerializer.string8,  # String(IA5), String(Printable)
        "2.5.5.6": ReplicationAttributeSerializer.string8,  # String(Numeric)
        "2.5.5.2": ReplicationAttributeSerializer.attrtyp,  # String(Object-Identifier)
        "2.5.5.12": ReplicationAttributeSerializer.string16,  # String(Unicode)
        "2.5.5.11": ReplicationAttributeSerializer.dsTime,  # String(UTC-Time), String(Generalized-Time)
        "2.5.5.1": ReplicationAttributeSerializer.dsName,  # Object(DS-DN)
        "2.5.5.14": ReplicationAttributeSerializer.syntaxDistnameBinary,  # Object(DN-String), Object(Access-Point)
        "2.5.5.7": ReplicationAttributeSerializer.syntaxDistnameBinary,  # Object(DN-Binary), Object(OR-Name)
        "2.5.5.15": ReplicationAttributeSerializer.securityDescriptor,  # String(NT-Sec-Desc)
        "2.5.5.17": ReplicationAttributeSerializer.sid,  # String(SID)
        "2.5.5.4": ReplicationAttributeSerializer.string8,  # String(Teletex)
    }

    def __init__(self, name="", value=None, oid=None, value_type=None):
        self.name: str = name
        self.value = value
        self.value_type = value_type
        self.oid = oid
        self.flags: int
        self.__enum()
        self.serialized = self.encode()

    @staticmethod
    def builder(attributes: Union[List[Dict], Dict]) -> List['ReplicationAttribute']:
        result = []
        if isinstance(attributes, List):
            for attr in attributes:
                result.append(ReplicationAttribute(name=attr["name"], value=attr["value"]))
        elif isinstance(attributes, Dict):
            for key, value in attributes.items():
                result.append(ReplicationAttribute(name=key, value=value, value_type=type(value)))
        return result

    def __enum(self):
        logger.debug(f"Enumerating info for attribute: {self.name}")
        ldap_client = SessionsManager().get_ldap()
        ldap_client.session.search(
            search_base=ldap_client.server.info.other["schemaNamingContext"][0],  # TODO mimikatz searched in the Configuration NC, don't why, but attributes are in the Schema NC, make sure we are doing the right thing here
            search_scope=SUBTREE,
            search_filter=f"(&(objectclass=attributeSchema)(lDAPDisplayName={self.name}))",
            attributes=[
                "attributeID",
                "attributeSyntax",
                "systemFlags"
            ]
        )
        if len(ldap_client.session.entries) == 1:
            self.oid = ldap_client.session.entries[0]['attributeID'][0]
            self.value_type = ldap_client.session.entries[0]['attributeSyntax'][0]
            self.flags = int(ldap_client.session.entries[0]['systemFlags'][0])
            logger.debug(f"└── OID: {self.oid}")
            logger.debug(f"└── Value type: {self.value_type}")
            logger.debug(f"└── Flags: {self.flags}")
        else:
            raise ValueError("Attribute not found")

    def encode(self) -> drsuapi.ATTR:
        encoded = ReplicationAttributeSerializer(oid=self.oid, value=self.value, serializer=self.__VALUE_TYPE_MAP[self.value_type]).serialize()
        logger.debug(f"└── Encoded attribute: {encoded.getData()}")
        return encoded
