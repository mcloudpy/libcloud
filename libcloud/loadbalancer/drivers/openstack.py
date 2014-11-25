# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

try:
    import simplejson as json
except ImportError:
    import json  # NOQA

from libcloud.loadbalancer.base import LoadBalancer, Member, Driver, Algorithm
from libcloud.loadbalancer.types import State
from libcloud.compute.drivers.openstack import OpenStackComputeConnection, OpenStack_1_1_NodeDriver, OpenStack_1_1_FloatingIpAddress
from neutronclient.neutron import client as nclient
from neutronclient.common.exceptions import NotFound, NeutronClientException

DEFAULT_ALGORITHM = Algorithm.ROUND_ROBIN
DEFAULT_SESSION_AFFINITY = None

class OpenStackLBDriver(Driver):
    connectionCls = OpenStackComputeConnection
    """
    Base OpenStack node driver. Should not be used directly.
    """
    api_name = 'openstack'
    name = 'OpenStack'
    website = 'http://openstack.org/'

    _VALUE_TO_ALGORITHM_MAP = {
        'ROUND_ROBIN': Algorithm.ROUND_ROBIN,
        'LEAST_CONNECTIONS': Algorithm.LEAST_CONNECTIONS,
        'SOURCE_IP': None, # TODO create new Algorithm?
    }

    # Statuses extracted from:
    #    https://wiki.openstack.org/wiki/Neutron/LBaaS/API
    _VIP_STATUS_TO_LB_STATE_MAP = {
        'ACTIVE': State.RUNNING,
        'PENDING_CREATE': State.PENDING,
        'PENDING_UPDATE': State.PENDING,
        'PENDING_DELETE': State.PENDING,
        'INACTIVE': State.UNKNOWN,
        'ERROR': State.ERROR,
        #'???': State.DELETED,
    }

    def __init__(self, *args, **kwargs):
        self.openstack = OpenStack_1_1_NodeDriver(*args, **kwargs)
        # TODO It should check ex_force_auth_version before and
        # throw an exception it is not the 2.0 version.  
        auth_url = kwargs['ex_force_auth_url']
        if not auth_url.endswith("/"):
            auth_url += "/"
        auth_url = "%sv2.0" % auth_url
        self.neutron = nclient.Client('2.0', username=self.openstack.key,
                                      password=self.openstack.secret,
                                      tenant_name=self.openstack._ex_tenant_name,
                                      auth_url=auth_url)
        self.connection = self.openstack.connection
        self.__create_algorithm_to_value_map()

    def __create_algorithm_to_value_map(self):
        for key, value in self._VALUE_TO_ALGORITHM_MAP.iteritems():
            self._ALGORITHM_TO_VALUE_MAP[value] = key

    def _get_node_from_ip(self, ip):
        """
        Return the node object that matches a given public IP address.

        :param  ip: Public IP address to search for
        :type   ip: ``str``

        :return:  Node object that has the given IP, or None if not found.
        :rtype:   :class:`Node` or None
        """
        all_nodes = self.openstack.list_nodes(ex_zone='all')
        for node in all_nodes:
            if ip in node.public_ips:
                return node
        return None

    def list_protocols(self):
        """
        Return a list of supported protocols.

        For OpenStack, this is simply a hardcoded list.

        :rtype: ``list`` of ``str``
        """
        return ['TCP', 'HTTP', 'HTTPS']

    def list_balancers(self, ex_region=None):
        """
        List all loadbalancers

        :keyword  ex_region: The region to return balancers from.  If None,
                             will default to self.region.  If 'all', will
                             return all balancers.
        :type     ex_region: ``str`` or :class:`GCERegion` or ``None``

        :rtype: ``list`` of :class:`LoadBalancer`
        """
        balancers = []
        for npool in self.ex_list_pools():
            balancers.append( self._get_balancer_neutron( npool ) )
        return balancers

    def _get_balancer_neutron(self, neutron_pool):
        """
        Return a :class:`LoadBalancer` object.
        :param  neutron_pool: Object returned by neutronclient
        :param: neutron_pool: ``dict``
        :param  balancer_id: Name of load balancer you wish to fetch.
                            For OpenStack, this is the id of the Pool.
        :param  balancer_id: ``str``

        :rtype: :class:`LoadBalancer`
        """
        try:
            vip = self.ex_get_vip(neutron_pool['vip_id'])
            port_obj = self.ex_get_port("vip-" + vip.id) # port name: "vip-[vip_id]"
            if port_obj: # not None # TODO what if its wrong?
                floating_ip = self.ex_get_floating_ip_by_port_id(port_obj['id'])
            return self._to_loadbalancer(self._to_pool(neutron_pool), floating_ip, vip)
        except NotFound:
            return self._to_loadbalancer(self._to_pool(neutron_pool))

    def get_balancer(self, balancer_id):
        """
        Return a :class:`LoadBalancer` object.

        :param  balancer_id: Name of load balancer you wish to fetch.
                            For OpenStack, this is the id of the Pool.
        :param  balancer_id: ``str``

        :rtype: :class:`LoadBalancer`
        """
        # Improvement: look for?
        #for vip in self.ex_list_vips(): # TODO implement ex_list_vips!
        #    if balancer_id == vip['pool_id']:
        #            vid = vip['id']
        #            break
        # TODO fix with balancer data?
        pool = self.ex_get_pool(balancer_id)
        vip = self.ex_get_vip_by_pool_id(balancer_id)
        return self._to_loadbalancer(pool, vip=vip)

    def create_balancer(self, name, port, protocol, algorithm, members,
                        ex_region=None, ex_address=None,
                        ex_session_affinity=None, ex_network_name=None,
                        ex_description=None,
                        ex_session_cookie_name=None): # or OpenStackNetwork?
        """
        Create a new load balancer instance.

        For OpenStack, this means creating a Pool and its VIP,
        then adding the members to the target pool.

        :param  name: Name of the new load balancer (required)
        :type   name: ``str``

        :param  port: Port or range of ports the load balancer should listen
                      on, defaults to all ports.  Examples: '80', '5000-5999'
        :type   port: ``str``

        :param  protocol: Load balancer protocol.  Should be 'TCP', 'HTTP' or 'HTTPS',
                          defaults to 'TCP'.
        :type   protocol: ``str``

        :param  members: List of Members to attach to balancer.  Can be Member
                         objects or Node objects.  Node objects are preferred
                         for GCE, but Member objects are accepted to comply
                         with the established libcloud API.  Note that the
                         'port' attribute of the members is ignored.
        :type   members: ``list`` of :class:`Member` or :class:`Node`

        :param  algorithm: Load balancing algorithm.
        :type   algorithm: :class:`Algorithm` or ``None``

        :keyword  ex_region:  Optional region to create the load balancer in.
                              Defaults to the default region of the GCE Node
                              Driver.
        :type     ex_region:  C{GCERegion} or ``str``

        :keyword  ex_address: Optional static address object to be assigned to
                              the load balancer.
        :type     ex_address: TODO

        :keyword  ex_session_affinity: Optional algorithm to use for session
                                       affinity.  This will modify the hashing
                                       algorithm such that a client will tend
                                       to stick to a particular Member.
        :type     ex_session_affinity: ``str``
        :keyword  ex_session_cookie_name: Name of the application cookie where
                                       session information will be stored.
                                       It should only be added if the session affinity
                                       is set to APP_COOKIE.
        :type     ex_session_cookie_name: ``str``

        :return:  LoadBalancer object
        :rtype:   :class:`LoadBalancer`
        """
        # Would it be better to throw custom exceptions?
        assert ex_session_affinity in self.ex_list_session_affinities()
        assert ex_session_affinity!='APP_COOKIE' or ex_session_cookie_name is not None, \
            "If the session affinity is APP_COOKIE, you must also provide a name for the cookie."

        
        pool = self.ex_create_pool(name, protocol, algorithm, ex_network_name, ex_description)
        vip = self.ex_create_vip(name, port, protocol, pool.subnet_id, pool.id,
                                     ex_session_affinity, ex_session_cookie_name)  
        
        if ex_address:
            try:
                floating_ip = self.ex_get_floating_ip(ex_address)
                port_obj = self.ex_get_port("vip-" + vip.id) # port name: "vip-[vip_id]"
                if port_obj and 'id' in port_obj:
                    port_id = port_obj['id']
                    # floating_ip attribute updated (although is not really needed)
                    floating_ip = self.ex_attach_floating_ip_to_port( floating_ip, port_id )
            except NeutronClientException as ne:
                # destroy the Pool and the Vip
                vip.destroy()
                pool.destroy()
                raise ne
        
        added_members = []
        for member in members:
            try:
                member_id = self.ex_create_member(pool.id, member)
                added_members.append(member_id)
            except NeutronClientException as ne: 
                # If it fails at any step, delete the target pool neutron.
                for member_id in added_members:
                    self.neutron.delete_member(member_id)
                # destroy the Pool and the Vip
                vip.destroy()
                pool.destroy()
                break # end for loop
        
        # Reformat forwarding rule to LoadBalancer object
        return self._to_loadbalancer(pool, floating_ip, vip)

    def destroy_balancer(self, balancer):
        """
        Destroy a load balancer.

        For OpenStack, this means destroying the attached VIP, then
        destroying the target pool that was associated with the VIP.

        :param  balancer: LoadBalancer which should be used
        :type   balancer: :class:`LoadBalancer`

        :return:  True if successful
        :rtype:   ``bool``
        """
        pool = self.ex_get_pool(balancer)
        try:
            vip = self.ex_get_vip(pool.vip_id)
            if not vip.destroy():
                return False
            else:
                pool_destroy = pool.destroy()
                return pool_destroy
        except NotFound:
            # no need to destroy an inexisting VIP
            return pool.destroy()

    def _to_loadbalancer(self, pool, floating_ip=None, vip=None):
        ip = None if floating_ip is None else floating_ip.ip_address
        port = None if vip is None else vip.protocol_port
        state = self._VIP_STATUS_TO_LB_STATE_MAP[pool.status] # will they be the same statuses?
        already_included = ('id', 'name', 'status', 'driver')
        extras = self._get_extra_dict(pool, already_included)
        # Should I fill "extra" with vip and floating_ip objects' useful info too?
        return LoadBalancer(id=pool.id,
                            name=pool.name, state=state,
                            ip=ip, port=port,
                            driver=self,
                            extra=extras)

    def balancer_attach_compute_node(self, balancer, node):
        """
        Attach a compute node as a member to the load balancer.

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param node: Node to join to the balancer
        :type  node: :class:`Node`

        :return: Member after joining the balancer.
        :rtype: :class:`Member`
        """
        member = self._node_to_member(node, balancer)
        return self.balancer_attach_member(balancer, member)


    def _node_to_member(self, node, balancer):
        """
        Return a Member object based on a Node.

        :param  node: Node object
        :type   node: :class:`Node`

        :keyword  balancer: The balancer the member is attached to.
        :type     balancer: :class:`LoadBalancer`

        :return:  Member object
        :rtype:   :class:`Member`
        """
        # A balancer can have a node as a member, even if the node doesn't
        # exist.  In this case, 'node' is simply a string to where the resource
        # would be found if it was there.
        member_ip = None
        if hasattr(node, 'name'):
            # We could also assert len(node.private_ips)==1
            # Or show a message like:
            #  """The node has more than one private addresses.
            #     This driver does not know how to discern which to use in the Load Balancer.
            #     Try adding the one you choose using 'balancer_attach_member' instead."""
            member_ip = node.private_ips[0]
        
        extra = {'node': node}
        # We could also show a warning message such as:
        # "WARNING. If you want to balance other port than the 80, please use the 'balancer_attach_member' method."
        return Member(id=None, ip=member_ip, port=balancer.port,
                      balancer=balancer, extra=extra)

    def balancer_attach_member(self, balancer, member):
        """
        Attach a member to balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param member: Member to join to the balancer
        :type member: :class:`Member`

        :return: Member after joining the balancer.
        :rtype: :class:`Member`
        """
        if member.id is None:
            return self.ex_create_member(balancer.id, member) # it's also attached
        else:
            node = {'pool_id':balancer.id}
            nmember = self.neutron.update_member(member.id, {'member':node})
            return None if nmember is None else self._to_member(nmember['member'])

    def balancer_detach_member(self, balancer, member):
        """
        Detach member from balancer (i.e., in OpenStack deletes it).

        :param balancer: LoadBalancer which should be used.
                        Note that the current OpenStack implementation
                        does not actually use this parameter.
        :type  balancer: :class:`LoadBalancer`

        :param member: Member which should be used
        :type member: :class:`Member`

        :return: True if member detach was successful, otherwise False
        :rtype: ``bool``
        """
        #mobj = self.neutron.update_member( {'member': {'pool_id': None } } ) # returns error
        try:
            self.neutron.delete_member(member.id)
            return True
        except NotFound:
            # IMO 'NotFound' exception would be much more descriptive that the boolean. :-S
            return False

    def ex_list_session_affinities(self):
        """
        Return a list of supported session affinities (or persistences).

        For OpenStack, this is simply a hardcoded list.

        :rtype: ``list`` of ``str``
        """
        return ['DISABLED', 'SOURCE_IP', 'HTTP_COOKIE', 'APP_COOKIE']

    def balancer_list_members(self, balancer):
        """
        Return list of members attached to balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :rtype: ``list`` of :class:`Member`
        """
        # Recheck it just in case it has been updated
        pool = self.ex_get_pool(balancer.id)
        balancer.extra['members'] = pool.members
        # if 'members' in balancer.extra: # now is always true
        ret = []
        for member_id in balancer.extra['members']:
            ret.append(self.ex_get_member(member_id))
        return ret

    def ex_list_pools(self):
        # TODO self.openstack.ex_list_loadbalancer
        # no me aclaro con self.connection
        # intento hacer a "http://bor.deusto.es:9696/v2.0/lb/pools.json",
        # pero toma de base bor.deusto.es:8774/v2/a79090daa2d8497389eb610f26a51870
        return self.neutron.list_pools()['pools']

    def ex_get_network_subnet_ids(self, network_name):
        for net in self.neutron.list_networks()['networks']:
            if net['name'] == network_name:
                return net['subnets']
        return None

    def ex_get_floating_ip(self, ip_address):
        fip = self.openstack.ex_get_floating_ip(ip_address)
        if fip: # is not empty
            return fip
        
        # try to "create" (allocate) it
        self.ex_create_floating_ip(ip_address)
        # there should be only one result, so avoid returning it as a list
        return self.openstack.ex_get_floating_ip(ip_address)
    
    def ex_get_floating_ip_by_port_id(self, port_id):
        for fip in self.neutron.list_floatingips()['floatingips']:
            if fip['port_id'] == port_id:
                return self._to_floating_ip(fip)
        return None

    def ex_create_floating_ip(self, id_address):
        # More general ex_create_floating_ip() exists in self.openstack
        request = {'floatingip': id_address} # we could associate it in the same operation
        return self.neutron.create_floatingip(request)

    def ex_attach_floating_ip_to_port(self, floating_ip, port_id):
        # More specific ex_attach_floating_ip_to_node exist in OpenStack class
        request = {'port_id': port_id}
        fip = self.neutron.update_floatingip(floating_ip.id, {'floatingip': request})
        return None if fip is None else self._to_floating_ip(fip['floatingip'])

    def _to_floating_ip(self, neutron_obj):
        return OpenStack_1_1_FloatingIpAddress(id=neutron_obj['id'],
                                               ip_address=neutron_obj['floating_ip_address'],
                                               pool=None,
                                               # FIXME a floating_ip can be associated to a balancer too
                                               node_id=None,
                                               driver=self)

    def ex_get_port(self, port_name):
        for port in self.neutron.list_ports()['ports']:
            if port['name'] == port_name:
                return port
        return None

    def ex_get_pool(self, pool_id):
        p = self.neutron.show_pool(pool_id)
        if p is None:
            return None
        return self._to_pool(p['pool'])

    def ex_create_pool(self, name, protocol, algorithm, ex_network_name, ex_description):
        subnet_id = self.ex_get_network_subnet_ids(ex_network_name)[0]
        pool = {'subnet_id':subnet_id, 
            'lb_method':self._algorithm_to_value(algorithm), 
            'protocol':protocol, 
            'name':name, 
            'description':ex_description, 
            'admin_state_up':True}
        pool_obj = self.neutron.create_pool({'pool':pool})
        return None if pool_obj is None else self._to_pool(pool_obj['pool'])

    def ex_delete_pool(self, pool_id):
        print self.neutron.delete_pool(pool_id)
        # TODO Capture the exception it throws if something goes wrong.
        return True

    def _to_pool(self, neutron_obj):
        return OpenStack_2_Pool(neutron_obj['id'],
                                neutron_obj['name'],
                                neutron_obj['description'],
                                neutron_obj['status'],
                                neutron_obj['protocol'],
                                neutron_obj['admin_state_up'],
                                neutron_obj['lb_method'],
                                neutron_obj['subnet_id'],
                                neutron_obj['vip_id'],
                                neutron_obj['provider'],
                                neutron_obj['status_description'],
                                neutron_obj['members'],
                                neutron_obj['health_monitors'],
                                neutron_obj['health_monitors_status'],
                                self )

    def ex_get_member(self, member_id):
        nmember = self.neutron.show_member(member_id)
        return self._to_member(nmember['member'])

    def ex_create_member(self, pool_id, member):
        assert member.ip, "The member should have an IP address."
        assert member.port, "The member should have a port."
        node = {'address':member.ip,
                'protocol_port':member.port,
                'pool_id':pool_id,
                'admin_state_up':True}
        # Member object
        weight = member.extra.get('weight')
        if weight:
            node['weight'] = weight
        
        mobj = self.neutron.create_member({'member':node})
        return None if mobj is None else mobj['member']['id']

    def _to_member(self, neutron_member):
        already_included = ('id', 'address', 'protocol_port')
        extras = self._get_extra_dict(neutron_member, already_included)
        return Member(neutron_member['id'], neutron_member['address'],
                      neutron_member['protocol_port'], extra=extras)

    def ex_list_vips(self):
        # TODO self.openstack.ex_list_loadbalancer
        # no me aclaro con self.connection
        # intento hacer a "http://bor.deusto.es:9696/v2.0/lb/pools.json",
        # pero toma de base bor.deusto.es:8774/v2/a79090daa2d8497389eb610f26a51870
        return self.neutron.list_vips()['vips']

    def ex_get_vip(self, vid):
        v = self.neutron.show_vip(vid)
        if v is None:
            return None
        return self._to_vip(v['vip'])

    def ex_get_vip_by_pool_id(self, pool_id):
        for v in self.ex_list_vips():
            if pool_id ==  v['pool_id']:
                return self._to_vip(v)
        return None

    def ex_create_vip(self, name, port, protocol, subnet_id, pool_id,
                      session_affinity=None, session_cookie_name=None):
        vip = { 'protocol':protocol, 
                'name':"vip_" + name, 
                'subnet_id': subnet_id,
                'pool_id':pool_id, 
                'protocol_port':port, 
                'admin_state_up':True }
        if session_affinity:
            vip['session_persistence'] = { 'type': session_affinity }
            if session_cookie_name:
                vip['session_persistence']['cookie_name'] = session_cookie_name
                            
        vip_obj = self.neutron.create_vip({'vip':vip})
        return None if vip_obj is None else self._to_vip(vip_obj['vip'])

    def ex_delete_vip(self, vip_id):
        self.neutron.delete_vip(vip_id)
        # TODO Capture the exception it throws if something goes wrong.
        return True

    def _to_vip(self, neutron_obj):
        return OpenStack_2_VIP( neutron_obj['id'],
                                neutron_obj['name'],
                                neutron_obj['description'],
                                neutron_obj['status'],
                                neutron_obj['protocol'],
                                neutron_obj['admin_state_up'],
                                neutron_obj['subnet_id'],
                                neutron_obj['tenant_id'],
                                neutron_obj['connection_limit'],
                                neutron_obj['pool_id'],
                                neutron_obj['session_persistence'],
                                neutron_obj['address'],
                                neutron_obj['protocol_port'],
                                neutron_obj['port_id'],
                                self )

    def _get_extra_dict(self, properties, ignore_fields):
        extras = {}
        if isinstance(properties, dict):
            for key in properties.iterkeys():
                if key not in ignore_fields:
                    extras[key] = properties[key]
        else: # to inspect object's attributes
            for attr in dir(properties):
                if not attr.startswith("_") and attr not in ignore_fields:
                    at_val = properties.__getattribute__(attr)
                    if not hasattr(at_val, '__call__'): # not a function
                        extras[attr] = at_val
        return extras

    def ex_list_health_monitor(self):
        ret = []
        for healthmonitors in self.neutron.list_health_monitors()['health_monitors']:
            ret.append(self._to_health_monitor(healthmonitors))
        return ret

    def ex_get_health_monitor(self, health_monitor_id):
        ret = []
        hm = self.neutron.show_health_monitor(health_monitor_id)['health_monitor']
        return self._to_health_monitor(hm)

    def ex_balancer_list_health_monitor(self, balancer):
        pool = self.ex_get_pool(balancer.id)
        ret = []
        for hm_id in pool.health_monitors:
            ret.append(self.ex_get_health_monitor(hm_id))
        return ret

    def ex_create_health_monitor(self, healthmonitor):
        hm = {'type':healthmonitor.type,
              'delay':healthmonitor.delay,
              'timeout':healthmonitor.timeout,
              'max_retries':healthmonitor.max_retries,
              'admin_state_up':healthmonitor.admin_state_up}
        if hm['type']=='HTTP' or hm['type']=='HTTPS':
            assert  healthmonitor.ex_status!=None and \
                    healthmonitor.ex_http_method!=None and \
                    healthmonitor.ex_url_path!=None and \
                    healthmonitor.ex_expected_codes!=None, \
                    "If the type is HTTP or HTTPS, you have to provide the extended arguments."
            hm['status'] = healthmonitor.ex_status
            hm['http_method'] = healthmonitor.ex_http_method
            hm['url_path'] = healthmonitor.ex_url_path
            hm['expected_codes'] = healthmonitor.ex_expected_codes
        hm_obj = self.neutron.create_health_monitor({'health_monitor':hm})
        return None if hm_obj is None else self._to_health_monitor(hm_obj['health_monitor'])

    def ex_delete_health_monitor(self, health_monitor_id):
        self.neutron.delete_health_monitor(health_monitor_id)
        # TODO Capture the exception it throws if something goes wrong.
        return True

    def ex_balancer_attach_health_monitor(self, balancer, healthmonitor):
        """
        Attach a healthcheck to balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param health_monitor: HealthMonitor to add
        :type  health_monitor: :class:`OpenStack_2_HealthMonitor`

        :return: True if successful
        :rtype:  ``bool``
        """
        if healthmonitor.id is None:
            self.ex_create_health_monitor(healthmonitor)
        body = {'health_monitor': {'id': healthmonitor.id}}
        self.neutron.associate_health_monitor(balancer.id, body)
        # If everything went successful (and no exceptions where thrown...)
        balancer.extra['health_monitors'].append(healthmonitor.id)
        healthmonitor.pools.append(balancer.id)
        return True

    def ex_balancer_detach_health_monitor(self, balancer, healthmonitor):
        """
        Detach healtcheck from balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param healthmonitor: HealthMonitor to remove
        :type  healthmonitor: :class:`OpenStack_2_HealthMonitor`

        :return: True if successful
        :rtype: ``bool``
        """
        self.neutron.disassociate_health_monitor(balancer.id, healthmonitor.id)
        # If everything went successful (and no exceptions where thrown...)
        balancer.extra['health_monitors'].remove(healthmonitor.id)
        healthmonitor.pools.remove(balancer.id)
        return True

    def _to_health_monitor(self, neutron_obj):
        return OpenStack_2_HealthMonitor( neutron_obj['id'],
                                neutron_obj['tenant_id'],
                                neutron_obj['type'],
                                neutron_obj['delay'],
                                neutron_obj['timeout'],
                                neutron_obj['max_retries'],
                                neutron_obj['admin_state_up'],
                                self,
                                # TODO Contains more data: 'status', 'status_description' and 'pool_id'
                                [p['pool_id'] for p in neutron_obj['pools']] if 'pools' in neutron_obj else None,
                                neutron_obj['http_method'] if 'http_method' in neutron_obj else None,
                                neutron_obj['url_path'] if 'url_path' in neutron_obj else None,
                                neutron_obj['expected_codes'] if 'expected_codes' in neutron_obj else None )

#===============================================================================
# "status":"ACTIVE",
# "protocol":"HTTP",
# "description":"",
# "admin_state_up":true,
# "subnet_id":"8032909d-47a1-4715-90af-5153ffe39861",
# "tenant_id":"83657cfcdfe44cd5920adaf26c48ceea",
# "connection_limit":1000,
# "pool_id":"72741b06-df4d-4715-b142-276b6bce75ab",
# "session_persistence":{
#     "cookie_name":"MyAppCookie",
#     "type":"APP_COOKIE"
# },
# "address":"10.0.0.10",
# "protocol_port":80,
# "port_id":"b5a743d6-056b-468b-862d-fb13a9aa694e",
## "id":"4ec89087-d057-4e2c-911f-60a3b47ee304",
## "name":"my-vip"
#===============================================================================
class OpenStack_2_VIP(object):
    """A OpenStack VIP class."""
    def __init__(self, id, name, description, status, protocol, admin_state_up,
                 subnet_id, tenant_id, connection_limit, pool_id,
                 session_persistence, address, protocol_port, port_id, driver):
        self.id = str(id)
        self.name = name
        self.description = description
        self.status = status
        self.protocol = protocol
        self.admin_state_up = admin_state_up
        self.subnet_id = subnet_id
        self.tenant_id = tenant_id
        self.connection_limit = connection_limit
        self.pool_id = pool_id
        self.session_persistence = session_persistence
        self.address = address
        self.protocol_port = protocol_port
        self.port_id = port_id
        self.driver = driver

    def destroy(self):
        """
        Destroy this VIP.

        :return:  True if successful
        :rtype:   ``bool``
        """
        return self.driver.ex_delete_vip(self.id)

    def __repr__(self):
        return '<OpenStack_2_VIP id="%s" name="%s" protocol="%s" status="%s">' % (
            self.id, self.name, self.protocol, self.status)

#===============================================================================
# FIXME: Difference between what the API returns and [1]. I should check the API version.
# [1] http://docs.openstack.org/api/openstack-network/2.0/content/GET_showPool__v2.0_pools__pool_id__lbaas_ext_ops_pool.html 
#===============================================================================
# Documentation says:
# id, name, description, status, protocol, admin_state_up, tenant_id, members,
# lb_algorithm, session_persistence & healthmonitor_id.
#===============================================================================
# API returns:
# id, name, description, status, protocol, admin_state_up, tenant_id, members,
# lb_method, subnet_id, vip_id, provider, status_description, health_monitors &
# health_monitors_status.
#===============================================================================
class OpenStack_2_Pool(object):
    """A OpenStack Pool class."""
    def __init__(self, id, name, description, status, protocol, admin_state_up,
                 lb_method, subnet_id, vip_id, provider, status_description,
                 members, health_monitors, health_monitors_status,
                 driver):
        self.id = str(id)
        self.name = name
        self.description = description
        self.status = status
        self.protocol = protocol
        self.admin_state_up = admin_state_up
        self.lb_method = lb_method
        self.subnet_id = subnet_id
        self.vip_id = vip_id
        self.provider = provider
        self.status_description = status_description
        self.members = members
        self.health_monitors = health_monitors
        self.health_monitors_status = health_monitors_status
        self.driver = driver

    def destroy(self):
        """
        Destroy this Pool.

        :return:  True if successful
        :rtype:   ``bool``
        """
        return self.driver.ex_delete_pool(self.id)

    def __repr__(self):
        return '<OpenStack_2_Pool id="%s" name="%s" protocol="%s" status="%s">' % (
            self.id, self.name, self.protocol, self.status)

class OpenStack_2_HealthMonitor(object):
    """A OpenStack Health Monitor."""
    def __init__(self, id, tenant_id, type, delay, timeout, max_retries,
                 admin_state_up, driver, pools=None, http_method=None,
                 url_path=None, expected_codes=None):
        # FIXME version differences:
        #    The v2 from the documentation has "status" but not "pools".
        #    The version from OS Icehouse returns "pools" but not "status".
        assert type in ('PING', 'TCP', 'HTTP', 'HTTPS'), \
                        "Type must be PING, TCP, HTTP or HTTPS."
        self.id = str(id)
        self.tenant_id = tenant_id
        self.type = type
        self.delay = delay
        self.timeout = timeout
        self.max_retries = max_retries
        self.admin_state_up = admin_state_up
        self.driver = driver
        self.pools = pools
        self.http_method = http_method
        self.url_path = url_path
        self.expected_codes = expected_codes        

    def destroy(self):
        """
        Destroy this orphaned  Health Monitor.

        :return:  True if successful
        :rtype:   ``bool``
        """
        return self.driver.ex_delete_health_monitor(self.id)

    def __repr__(self):
        return '<OpenStack_2_HealthMonitor id="%s" tenant_id="%s" type="%s">' % (
            self.id, self.tenant_id, self.type)