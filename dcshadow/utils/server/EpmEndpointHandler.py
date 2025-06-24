from R2Log import logger

from dcshadow.utils.server.RpcServer import RPCServerHandler
from impacket import uuid
from impacket.dcerpc.v5 import epm

MSRPC_UUID_PORTMAP = ("E1AF8308-5D1F-11C9-91A4-08002B14A0FA", "3.0")
MSRPC_UUID_DRSUAPI = ("E3514235-4B06-11D1-AB04-00C04FC2DCD2", "4.0")
NDRSyntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class EPMEndpointHandler(RPCServerHandler):
    def setup(self):
        RPCServerHandler.setup(self)
        # self.transport = DCERPCServer(self.request)
        # logging.debug(f"RPCD: Received connection from {self.client_address[0]}")
        self.EPMCallbacks = {
            # 2: self.EPMlookup,
            3: self.EPMmap,
        }
        self.transport.addCallbacks(MSRPC_UUID_PORTMAP, "135", self.EPMCallbacks)

    def EPMmap(self, data):
        def floor_len(partial_tower):
            # The floor count, LHS byte count and RHS byte count are all 2-bytes, in little endian format.
            _cursor = 0
            lhs = int.from_bytes(partial_tower[_cursor:_cursor + 2], 'little')
            _cursor += 2 + lhs
            rhs = int.from_bytes(partial_tower[_cursor:_cursor + 2], 'little')
            _cursor += 2 + rhs
            return 2 + lhs + 2 + rhs

        logger.debug("EPM: Mapping request received")
        request = epm.ept_map(data)
        tower = epm.EPMTower()
        # request.dump()
        request_tower = b''.join(request['map_tower']['tower_octet_string'])
        _cursor = 0
        tower['NumberOfFloors'] = int.from_bytes(request_tower[_cursor:_cursor + 2], 'little')  # floor_count is 2 bytes
        _cursor += 2
        if tower['NumberOfFloors'] > 5:
            raise NotImplementedError("RPC EPM Map request unsupported (too many floors in tower)")
        for floor in range(tower['NumberOfFloors']):
            floor_data = request_tower[_cursor:_cursor + floor_len(request_tower[_cursor:])]
            if floor == 0:  # RPC interface identifier
                interface = epm.EPMRPCInterface(data=floor_data)
            elif floor == 1:  # RPC Data representation identifier
                dataRep = epm.EPMRPCDataRepresentation(data=floor_data)
            elif floor == 2:  # RPC protocol identifier
                protId = epm.EPMProtocolIdentifier(data=floor_data)
            elif floor == 3:  # Port address
                portAddr = epm.EPMPortAddr(data=floor_data)
            elif floor == 4:  # Host address
                hostAddr = epm.EPMHostAddr(data=floor_data)
            _cursor += floor_len(request_tower[_cursor:])
        requested_uuid = uuid.bin_to_string(interface['InterfaceUUID'])
        if requested_uuid == MSRPC_UUID_DRSUAPI[0]:
            response = epm.ept_mapResponse()
            portAddr['IpPort'] = 1337  # TODO this is ugly, any more elegant way to get the DRSUAPI Endpoint port?
            # portAddr['IpPort'] = self.server.drs_port  # TODO this is ugly, any more elegant way to get the DRSUAPI Endpoint port?
            tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + portAddr.getData() + hostAddr.getData()
            response_tower = epm.twr_p_t()
            response_tower['tower_octet_string'] = tower.getData()
            response_tower['tower_length'] = len(tower)
            response['ITowers'] = [response_tower]
            response['num_towers'] = len(response['ITowers'])
            # response['ITowers'][0].fields['ReferentID'] = 3  # if the DC ignores the port answered, uncomment this, but normally it shouldn't be needed
            response.fields['ITowers'].fields['MaximumCount'] = 4  # don't know why but without this field, or if wrong, the DC ignore the port answered TODO: understand and make this dynamix
            logger.debug("EPM: sending Map response")
            return response
        else:
            raise NotImplementedError('Not a DRSUAPI Map request')
