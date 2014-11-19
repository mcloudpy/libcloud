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
from libcloud.compute.drivers.openstack import OpenStackComputeConnection, OpenStack_1_1_NodeDriver
from neutronclient.neutron import client as nclient
from neutronclient.common.exceptions import NeutronClientException

DEFAULT_ALGORITHM = Algorithm.ROUND_ROBIN


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


    def __init__(self, *args, **kwargs):
        self.openstack = OpenStack_1_1_NodeDriver(*args, **kwargs)
        
        ex_force_auth_url = "http://bor.deusto.es:35357/v2.0"
        self.neutron = nclient.Client('2.0', username=self.openstack.key, password=self.openstack.secret, tenant_name=self.openstack._ex_tenant_name, auth_url=ex_force_auth_url)

        self.connection = self.openstack.connection
        self.create_algorithm_to_value_map()

    def create_algorithm_to_value_map(self):
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
        for lb in self.ex_list_pools():
	    vip = self.ex_get_vip( lb['vip_id'] )
	    floating_ips = self.ex_list_floating_ips() # self.openstack does not return ports
	    ip_obj = None
	    for x in floating_ips:
		if x['port_id'] == vip['port_id']:
		    ip_obj = x['floating_ip_address']
            balancers.append(self._pool_to_loadbalancer(lb, vip['protocol_port'], ip_obj))
        return balancers        

    def create_balancer(self, name, port, protocol, algorithm, members,
                        ex_region=None, ex_healthchecks=None, ex_address=None,
                        ex_session_affinity=None, ex_network_name=None,
                        ex_description=None): # or OpenStackNetwork?
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

        :keyword  ex_healthchecks: Optional list of healthcheck objects or
                                   names to add to the load balancer.
        :type     ex_healthchecks: ``list`` of :class:`GCEHealthCheck` or
                                   ``list`` of ``str``

        :keyword  ex_address: Optional static address object to be assigned to
                              the load balancer.
        :type     ex_address: TODO

        :keyword  ex_session_affinity: Optional algorithm to use for session
                                       affinity.  This will modify the hashing
                                       algorithm such that a client will tend
                                       to stick to a particular Member.
        :type     ex_session_affinity: ``str``

        :return:  LoadBalancer object
        :rtype:   :class:`LoadBalancer`
        """
        pool_obj = self.ex_create_pool(name, protocol, algorithm, ex_network_name, ex_description)
        pool_id = pool_obj['id']
        
        vip_obj = self.ex_create_vip(name, port, protocol, pool_obj['subnet_id'], pool_id)
        vip_id = vip_obj['id']
        
        if ex_address:
            try:
                floating_ip = self.ex_get_floating_ip(ex_address)
                port_obj = self.ex_get_port("vip-" + vip_id) # port name: "vip-[vip_id]"
                if port_obj and 'id' in port_obj:
                    port_id = port_obj['id']
                    floatingip_obj = self.ex_attach_floating_ip_to_port( floating_ip.id, port_id )
            except NeutronClientException as ne:
                # destroy the Pool and the Vip
                self.neutron.delete_vip(vip_id)
                self.neutron.delete_pool(pool_id)
                raise ne
        
        added_members = []
        for member in members:
            try:
                member_id = self.ex_create_member(pool_id, member)
                added_members.append(member_id)
            except NeutronClientException as ne: 
                # If it fails at any step, delete the target pool neutron.
                for member_id in added_members:
                    self.neutron.delete_member(member_id)
                # destroy the Pool and the Vip
                self.neutron.delete_vip(vip_id)
                self.neutron.delete_pool(pool_id)
                break # end for loop
        
        # Reformat forwarding rule to LoadBalancer object
        return self._pool_to_loadbalancer(pool_obj, floatingip_obj['floatingip'], vip_obj)
    
    def _pool_to_loadbalancer(self, pool, floatingip, vip):
        return LoadBalancer(id=pool['id'],
                            name=pool['name'], state=pool['status'],
                            ip=floatingip['floating_ip_address'],
                            port=vip['protocol_port'],
                            driver=self, extra=None)

    def destroy_balancer(self, balancer):
        """
        Destroy a load balancer.

        For GCE, this means destroying the associated forwarding rule, then
        destroying the target pool that was attached to the forwarding rule.

        :param  balancer: LoadBalancer which should be used
        :type   balancer: :class:`LoadBalancer`

        :return:  True if successful
        :rtype:   ``bool``
        """
        destroy = balancer.extra['forwarding_rule'].destroy()
        if destroy:
            tp_destroy = balancer.extra['targetpool'].destroy()
            return tp_destroy
        else:
            return destroy

    def get_balancer(self, balancer_id):
        """
        Return a :class:`LoadBalancer` object.

        :param  balancer_id: Name of load balancer you wish to fetch.  For GCE,
                             this is the name of the associated forwarding
                             rule.
        :param  balancer_id: ``str``

        :rtype: :class:`LoadBalancer`
        """
        fwr = self.openstack.ex_get_forwarding_rule(balancer_id)
        return self._pool_to_loadbalancer(fwr)

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
        add_node = balancer.extra['targetpool'].add_node(node)
        if add_node:
            return self._node_to_member(node, balancer)

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
        node = member.extra.get('node') or self._get_node_from_ip(member.ip)
        add_node = balancer.extra['targetpool'].add_node(node)
        if add_node:
            return self._node_to_member(node, balancer)

    def balancer_detach_member(self, balancer, member):
        """
        Detach member from balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param member: Member which should be used
        :type member: :class:`Member`

        :return: True if member detach was successful, otherwise False
        :rtype: ``bool``
        """
        node = member.extra.get('node') or self._get_node_from_ip(member.ip)
        remove_node = balancer.extra['targetpool'].remove_node(node)
        return remove_node

    def balancer_list_members(self, balancer):
        """
        Return list of members attached to balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :rtype: ``list`` of :class:`Member`
        """
        return [self._node_to_member(n, balancer) for n in
                balancer.extra['targetpool'].nodes]

    def ex_list_pools(self):
        # TODO self.openstack.ex_list_loadbalancer
        # no me aclaro con self.connection
        # intento hacer a "http://bor.deusto.es:9696/v2.0/lb/pools.json",
        # pero toma de base bor.deusto.es:8774/v2/a79090daa2d8497389eb610f26a51870
        return self.neutron.list_pools()['pools']
      
    def ex_get_vip(self, vid):
        return self.neutron.show_vip(vid)['vip']
  
    def ex_get_network_subnet_ids(self, network_name):
        for net in self.neutron.list_networks()['networks']:
            if net['name'] == network_name:
                return net['subnets']
        return None

    def ex_list_floating_ips(self):
      return self.neutron.list_floatingips()['floatingips']

    def ex_get_floating_ip(self, ip_address):
        fip = self.openstack.ex_get_floating_ip(ip_address)
        if fip: # is not empty
            return fip[0]
        else: # try to "create" (allocate) it
            self.ex_create_floating_ip(ip_address)
            # there should be only one result, so avoid returning it as a list
            return self.openstack.ex_get_floating_ip(ip_address)[0]

    def ex_create_floating_ip(self, id_address):
        # More general ex_create_floating_ip() exists in self.openstack
        request = {'floatingip': id_address} # we could associate it in the same operation
        return self.neutron.create_floatingip(request)

    def ex_attach_floating_ip_to_port(self, floating_ip_id, port_id):
        # More specific ex_attach_floating_ip_to_node exist in OpenStack class
        request = {'port_id': port_id}
        return self.neutron.update_floatingip(floating_ip_id, {'floatingip': request})

    def ex_get_port(self, port_name):
        for port in self.neutron.list_ports()['ports']:
            if port['name'] == port_name:
                return port
        return None

    def ex_create_pool(self, name, protocol, algorithm, ex_network_name, ex_description):
        subnet_id = self.ex_get_network_subnet_ids(ex_network_name)[0]
        pool = {'subnet_id':subnet_id, 
            'lb_method':self._algorithm_to_value(algorithm), 
            'protocol':protocol, 
            'name':name, 
            'description':ex_description, 
            'admin_state_up':True}
        pool_obj = self.neutron.create_pool({'pool':pool})
        return None if pool_obj is None else pool_obj['pool']

    def ex_create_vip(self, name, port, protocol, subnet_id, pool_id):
        vip = {'protocol':protocol, 
            'name':"vip_" + name, 
            'subnet_id': subnet_id,
            'pool_id':pool_id, 
            'protocol_port':port, 
            'admin_state_up':True}
        vip_obj = self.neutron.create_vip({'vip':vip})
        return None if vip_obj is None else vip_obj['vip']

    def ex_create_member(self, pool_id, member):
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

    def ex_create_healthcheck(self, *args, **kwargs):
        return self.openstack.ex_create_healthcheck(*args, **kwargs)

    def ex_list_healthchecks(self):
        return self.openstack.ex_list_healthchecks()

    def ex_balancer_attach_healthcheck(self, balancer, healthcheck):
        """
        Attach a healthcheck to balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param healthcheck: Healthcheck to add
        :type  healthcheck: :class:`GCEHealthCheck`

        :return: True if successful
        :rtype:  ``bool``
        """
        return balancer.extra['targetpool'].add_healthcheck(healthcheck)

    def ex_balancer_detach_healthcheck(self, balancer, healthcheck):
        """
        Detach healtcheck from balancer

        :param balancer: LoadBalancer which should be used
        :type  balancer: :class:`LoadBalancer`

        :param healthcheck: Healthcheck to remove
        :type  healthcheck: :class:`GCEHealthCheck`

        :return: True if successful
        :rtype: ``bool``
        """
        return balancer.extra['targetpool'].remove_healthcheck(healthcheck)

    def ex_balancer_list_healthchecks(self, balancer):
        """
        Return list of healthchecks attached to balancer

        :param  balancer: LoadBalancer which should be used
        :type   balancer: :class:`LoadBalancer`

        :rtype: ``list`` of :class:`HealthChecks`
        """
        return balancer.extra['healthchecks']

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
        if hasattr(node, 'name'):
            member_id = node.name
            member_ip = node.public_ips[0]
        else:
            member_id = node
            member_ip = None

        extra = {'node': node}
        return Member(id=member_id, ip=member_ip, port=balancer.port,
                      balancer=balancer, extra=extra)