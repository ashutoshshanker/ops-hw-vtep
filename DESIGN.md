# High Level design of HW VTEP (virtual tunnel endpoint) High Level Design


## Contents

- [Description](#description)
- [Architectural Diagram](#architectural-diagram)
- [Design choices](#design-choices)
- [Unsupported features](#unsupported-features)
- [Key Components](#key-components)
- [OVSDB schema changes](#ovsdb-schema-changes)
- [Sync HW VTEP to OVSDB](#sync-hw-vtep-to-ovsdb)
- [Sync OVSDB to HW VTEP](#sync-ovsdb-to-hw-vtep)
- [OVSDB daemon support for HW VTEP](#ovsdb-daemon-support-for-hw-vtep)
- [Setting VXLAN tunnels](#setting-vxlan-tunnels)
- [Port binding to a VXLAN tunnel](#port-binding-to-a-vxlan-tunnel)
- [MAC binding to a VXLAN tunnel](#mac-binding-to-a-vxlan-tunnel)
- [MAC learning on a VXLAN tunnel](#mac-learning-on-a-vxlan-tunnel)
- [CLI and debug utility](#cli-and-debug-utility)
- [Provider API](#provider-api)
- [Simulation Provider support](#simulation-provider-support)
- [ASIC Provider support](#asic-provider-support)
- [Appendix](#appendix)
- [References](#references)

<div id='description'>
## Description

HW VTEP creates an overlay network to connect VMs to other VMs and/or to
physical switches by extending L2 forwarding domain over an L3 network.
HW VTEP can support a variety of tunneling protocols but the most deployed one
is VXLAN. The HW VTEP sits in between a network controller and an OpenSwitch.
The network controller is responsible for configuring network topology by
updating a HW VTEP database on all the VTEPs in the logical network.
Physical switches are responsible for exporting their own physical topology to
the HW VTEP database. This design describes the software changes required
to implement HW VTEP support on OpenSwitch. The design is flexible enough to
support multiple network controllers including OVN and NSX.
The design allows multiple tunneling protocols but initial implementation targets
VXLAN tunnels.
The HW VTEP may run on a real ASIC but it can also execute in simulation
(container plugin) mode.

<div id='architectural-diagram'/>
## Architectural diagram

```
<pre>

   +-------------------------- Logical Network --------------------------+
   |                                                                     |
   |                         Network Controller (OVN)                    |
   |                                 |                                   |
   |                                 |                                   |
   |                           HW VTEP database                          |
   |                                 |                                   |
   |                                 |                                   |
   |                             VTEP daemon                             |
   |                                 |                                   |
   |                                 |                                   |
   |                              OVS database                           |
   |                                 |                                   |
   |                                 |                                   |
   |                              bridge.c                               |
   |                                 |                                   |
   |                                 |                                   |
   |       Tunnel         +---------------------+    Tunnel              |
   | L2/L3 add/learn      |                     |   Creation             |
   |                      |                     |                        |
   |                   ofproto                netdev                     |
   |                      |                     |                        |
   |                      |                     |                        |
   |                ofproto provider       netdev provider               |
   |                      |                     |                        |
   |                      |                     |                        |
   |                      +---------------------+                        |
   |                                 |                                   |
   |                                 V                                   |
   |                        SIMULATION/ASIC API                          |
   |                                                                     |
   +---------------------------------------------------------------------+

</pre>
```

<div id='design-choices'/>
## Design choices

* Develop a high performance daemon to map HW VTEP to/from OVSDB
  OpenvSwitch distribution includes an ovs-vtep python script that scans the
  HW VTEP database, creates tunnels and executes open flow requests by using
  ovs-vsctl and ovs-ofctl.
  The development team considered using this script as a base line but ruled
  against it since python is not high performance enough to support
  state transitions of a scaled up data center with 100K+ interfaces in a
  logical network. Instead, the HW VTEP shim (translation) daemon is written
  in C and uses direct database R/W, rather than ovs-vsctl requests.

* HW VTEP database updates from vswitchd
  vswitchd could read and write to HW VTEP database, directly. This design
  is more efficient but its not modular and limited to HW VTEP schema.

* MAC learning
  MAC learning is a generic L2 feature that is needed outside the scope of
  HW VTEP. But since HW VTEP is the first application requiring sharing MAC
  entries from the controller, a subset of MAC learning features, sufficient
  to support HW VTEP is developed as part of this project. The design takes
  generic L2 requirements into account (mainly, for scale out) but does not
  offer full feature set to support L2 MAC learning.

<div id='unsupported-features'/>
## Unsupported features

The following OVN/SDN controller features are not supported at this time:

* L3 Multicast - Not required for data center deployment.
* BFD          - OVN should support HW VTEPs that disable BFD.

<div id='key-components'/>
## Key Components

* Set up global VTEP table.
* Register with a Network Controller via a service file and program manager table.
* Configure port to tunnel binding.
* Populate physical switch and physical port tables in HW VTEP database.
* Create and reconfigure tunnels.
* Configure unicast replication discovery of VTEP peer - ASIC only.
* Update local Ucast/Mcast MACs by ASIC learning on tunneled local ports.
* Update remote Ucast/Mcast MACs from HW VTEP database.
* Attach ports and MACs to tunnels.
* Develop VXLAN ASIC provider, including ASIC APIs.
* Develop VXLAN simulation provider using OpenvSwitch as "ASIC".
* ovs-vsctl enhancement to create VXLAN tunnels as required by the ASIC.
* ovs-vsctl enhancement to bind a VNI to VLAN while configuring a port.
* CLI to report logical switch state and stats.

<div id='ovsdb-schema-changes'/>
## OVSDB schema changes

* Modify interface table to support VXLAN tunnel type.
  Set interface options required by the implementation (e.g. tunnel source IP).
* Modify port table to include a key-value map of VLAN to tunnel key (VNI).
* Define a MAC table to store local and remote MACs.
  Local MACs are learned by the switch on access ports, written to OVSDB and
  then, synced to HW VTEP database.
  Remote MACs are published by the network controller and are used to add
  MAC/IP entries to tunnels in order to avoid flooding and employ ARP
  suppression.
* Add a logical switch table indexed by tunnel key.
  This tabled is used to store tunnel key multicast group, packet stats etc.
  Note: This table is not supported in first release.

<div id='sync-hw-vtep-to-ovsdb'/>
## Sync HW VTEP to OVSDB

The HW VTEP daemon uses these key HW VTEP tables to program OVSDB:

* Physical_Locator - VTEP IP address and tunnel type (VXLAN).
* Physical_Switch -  Port binding and tunnels (if programmed by a NW ctrl).
* Logical_Router -   IP prefix to Logical switch binding (optional).
* Logical_Switch -   Logical network name and tunnel key (VNI).
* Physical_locator - Tunnel endpoint location (IP address) on the network.

ovs-vtep is a Python script that creates VXLAN tunnels and generates open flow
requests by polling the HW VTEP database. vtepd daemon implements similar
features and its based on the ovs-vtep script.
vtepd is written in C (instead of Python) it executes direct database
transactions rather than ovs-vsctl and ovs-ofctl commands.
vtepd creates VXLAN tunnel interfaces and program access port to tunnel key
binding by updating port table in OVSDB.
vtepd programs destination MACs by updating the MAC table in OVSDB.
vteps supports a scaled up network and can interoperate with different network
controllers.

<div id='sync-ovsdb-to-hw-vtep'/>
## Sync OVSDB to HW VTEP

OVSDB maintains tunnel interfaces and access port bindings to tunnel keys.
vswitchd learns local MACs on the ports and updates the MAC
table. vtepd is responsible to sync that table to HW VTEP database.
When that happens, the network controller distributes the physical switch
information across the VTEPs in the network.

<div id='ovsdb-daemon-support-for-hw-vtep'/>
## OVSDB daemon support for HW VTEP

Tunnel support in OpenSwitch is added back. This includes tunnel types in
in the schema, creation of logical interfaces of tunnel type in ovs-vsctl,
and adding netdev-vport support to netdev ASIC provider as well as netdev
simulation provider.

The bridge (vswitchd) is enhanced to create tunnels and program traffic flows
by binding an access port to a tunnel key domain object.
Tunnel setting is performed by implementing netdev-vport class functions to
create/delete tunnels and by enhancing bundle\_set class function in ofproto
provider to assign/unassign ports to tunnels.
Tunnel routing is set by binding an egress port to a tunnel on a next hop
change. ofproto provider add/del l3\_host\_entry is enhanced to look up
tunnel destination IP and invoke tunnel binding to a new next hop egress port.

The bridge module invokes ofproto functions to add known DMACs and, optionally,
destination IP on the tunnels. This data is distributed by the network
controller to avoid "flood and learn".

The bridge module registers a MAC learning callback. It wakes up vswitchd
on MAC a single MAC update or a burst of MAC updates.
vswitchd wakes up and populates/updates the entries in the MAC table.

<div id='setting-vxlan-tunnels'/>
## Setting VXLAN tunnels

The HW VTEP has to create L (local) * R (remote) tunnels from the physical switch
to all the VTEPs in the network. Each tunnel may carry a single tunnel key or may
support multiple traffic flows with different tunnel keys.

The set of local (source) VTEP IP endpoint is determined by the list of tunnel
IPs in our physical switch table. The set of remote (destination) tunnel
endpoints is determined by the set of tunnel IP endpoints in the physical
locator table.

OVS implements tunnels via a netdev class, which calls a set of function in
netdev-vport.c. OpenSwitch removed any tunneling support but, now, this
functionality is added back, including schema support for tunnel types.
The netdev provider has to invoke netdev-vport functions, which trigger
a call to instantiate a tunnel in ASIC (BCM) or simulated ASIC (simulation).

<div id='port-binding-to-a-vxlan-tunnel'/>
## Port binding to a VXLAN tunnel

In order to tunnel packets over a given tunnel, a tunnel/VNI must be created
and a valid VLAN to VNI mapping must exist. The bridge (bridge.c) port\_configure
call looks up VLAN to tunnel key binding and if one exists, copies the binding
key-value pair (smap) pointer to the ofproto\_bundle\_setting structure in order
to pass this data to bundle\_set in the ofproto provider.

<div id='mac-binding-to-a-vxlan-tunnel'/>
## MAC binding to a VXLAN tunnel

The bridge software (bridge.c) polls the MAC table for remote MAC changes. When
it detects a change, it invokes ofproto provider add mac class function.

ofproto looks up the tunnel key on that MAC. When a new tunnel key is added,
the very first time, it creates a logical switch domain object for that key.
It also binds the logical switch with a physical tunnel based on destination
IP match.

<div id='mac-learning-on-a-vxlan-tunnel'/>
## MAC learning on a VXLAN tunnel

The bridge module registers a MAC learning callback. The provider maintains a
hash of new/deleted learned MACs and wakes up vswitchd poll\_block using a seq\_change
update. vswitchd then wakes up and updates up to a maximum of N MACs to OVSDB in one run.

<div id='cli-and-debug-utility'/>
## CLI and debug utility

The networks controller is responsible for configuring tunnels, tunnel ports,
as well as MAC/IP assignment to tunnels. It alleviates any need for CLI to do
the same. Non HW VTEP applications (e.g. Campus switching) require CLI to
setup tunnel topology but that is outside the scope of this document.

The system must still provide debugging facility. Hence, ovs-vsctl add-port
function are enhanced to provide a few additional parameters, including
an optional tunnel key as well as an optional source IP address for a tunnel
interface.

One area that requires CLI is controller configuration - i.e. how to reach the
controller.

<div id='provider-api'/>
## Provider API

* Tunnel setup

  Tunnel create/delete/update uses OVS tunnel creation convention.
  A new vxlan tunnel is created by adding an interface of type vxlan.
  Similarly, a tunnel is modified and deleted.
  When a tunnel is created, the OVS tunnel port is hashed using the
  destination IP address as a hash key.
  Initially, the tunnel is created in shutdown state.

  The following must happen to complete tunnel bring up:

  (1) Next Hop lookup for destination IP. On match, call add\_l3\_host\_entry.

  (2) On failure to find next hop, invoke longest IP prefix match.

  (3) On failure wait and repeat 2. On success, execute an arp on neighbor
     interface found in step 2. Wait and repeat step 1.

* Tunnel reconfiguration

  Tunneled packets are sent over next hop egress port. ASIC implementation may
  allow dynamic L3 route lookup on destination IP find egress port.
  Other implementation require specific next hop binding to tunnel on any next
  hop setup or next hop change. A next hop change results is a call to
  l3\_host\_entry in ofproto provider. The function invokes a tunnel hash lookup
  on the input IP address. A match indicates that a new next hop egress port
  has to be assigned to that tunnel.

* Access port binding

  ofproto\_bundle\_settings structure is expanded to include vlan to tunnel-key
  binding smap. port\_configure function in bridge.c has to set it up before
  invoking ofproto\_bundle\_register.
  ofproto can bind the port to a tunnel key object. Logical switch binding
  to a tunnel key K is only possible if a tunnel with key=K exists.
  Otherwise, binding of the tunnel key object to tunnel is done based on
  destination IP during MAC binding.

* MAC binding

  A new ofproto function to program destination MAC.
  Bridge.c looks for remote MAC updates in MAC table. It then invokes a new
  ofproto function to statically configure the new MAC on the tunnel.
  Using the tunnel key and tunnel destination IP for the MAC, it can bind
  the tunnel key to a tunnel.

* MAC learning

  A new ofproto provider function to return N learned MACs. See MAC learning.


<div id='simulation-provider-support'/>
## Simulation Provider support

* Create Tunnels

  The VTEP daemon creates an OVSDB tunnel by adding a tunnel to interface table.
  The bridge invokes netdev to add a tunnel whenever a tunnel interface is added.
  The netdev provider instructs the "ASIC" OVS to create a tunnel. Its done by
  creating a logical interface of type VXLAN, tunnel key (VNI) as well as local
  and remote endpoint IP address of the tunnel via /opt/openvswitch/bin/ovs-vsctl
  CLI. Similarly, tunnel deletion and modification will result in netdev provider
  deleting a tunnel by executing an ovs-vsctl command to delete the tunnel
  interface in "ASIC" OVS. Modifying a tunnel is done by deleting existing tunnel
  and creating a new one with alternate tunnel parameters by issuing an ovs-vsctl
  command.

* Assigning ports to VXLAN tunnels

  The simulation inserts an Open Flow rule to bind the local port to a VXLAN
  tunnel key. The bridge scans the port table for changes. When a local port is
  bound to a VNI the simulation provider will, then, insert proper Open Flow rules
  by executing/opt/openvswitch/bin/ovs-ofctl. The inverse happens on VNI unbound.

* Local MAC/IP addition to a tunnel

  The simulation adds bridge logic to watch for MAC learning on tunnels and updates
  the local Ucast/Mcast MAC table, accordingly.

* Remote MAC/IP addition to a tunnel

  The simulation adds bridge logic to watch for remote Ucast/Mcast MAC table updates.
  It also implements an ofproto/provider function to insert an open flow rule to tunnel
  L2 packets with this DMAC to the proper interface as well as insert a similar
  ARP rule for ARP suppression.

<div id='asic-provider-support'/>
## ASIC Provider support

* Create Tunnels

  The VTEP daemon creates an OVSDB tunnel by adding a tunnel to interface table.
  The bridge invokes netdev to add a tunnel whenever a tunnel interface is added.
  The netdev provider instructs the ASIC to create a tunnel. Similarly, tunnel
  deletion and modification will result in netdev provider deleting a tunnel by
  invoking the ASIC API to do so. Modifying a tunnel is done by deleting existing
  tunnel and creating a new one with alternate tunnel parameters.

* Assigning ports to VXLAN tunnels

  The provider invokes an ASIC API to bind the local port to a VXLAN tunnel
  key. The bridge scans the port table for changes. When a local port is bound to
  a VNI, ofproto provider function is called. The inverse happens on VNI
  unbound.

* Local MAC/IP addition to a tunnel

  The provider adds bridge logic to watch for MAC learning on tunnels and update the
  local Ucast/Mcast MAC table in OVSDB, accordingly.

* Remote MAC/IP addition to a tunnel

  The provider add bridge logic to watch for remote Ucast/MAC MAC table updates.
  It also invokes an ofproto/provider function to instruct the ASIC to tunnel
  L2 packets with this DMAC to the proper interface as well as insert a static
  ARP entry in our proxy ARP.

* Proxy ARP
  Implement a proxy ARP in Linux kernel. Register with ASIC to punt ARP requests
  to control plane. Insert static ARP entries from on remote MAC/IP updates.
  May support multiple proxy ARP instances by assigning each one to a different
  name space.
  an ofproto class function call

<div id='appendix'/>
## Appendix

### HW VTEP database programming (who does what)

#### HW Switch (HSC)

* Create vtep database, adds it to ovsdb-server.
* Add the Physical switch that implements VTEP to the HW VTEP database.
* Set the local terminating tunnel endpoints IP addresses in the Physical Switch Table.
* Initiate connection with the NVC.
* Publish locally learned Macs in the Macs local Table as it learns MACs on the VTEP.
* Update the local unicast and mcast MAC in the Macs local Table as it learns them on the VTEP.
* Create or delete VXLAN tunnels depending on the remote Mac mapping given by the NVC.
* Update stats.

#### Network controller (NVC)

* Set logical Switch and VNI (VXLAN tunnel key).
* Set the Remote tunnel IP in physical locator.
* Populate the access ports in the physical port table and set vlan to vni binding.
* Update the remote unicast/mcast.
* Instruct to bind the access port (with or without vlan) to a VNI.
* Publish remotely learned mcast MAC and the multicast IP to reach it.

<div id='references'/>
## References

* [openswitch](http://www.openswitch.net/)
* [OpenvSwitch](http://www.openvswitch.org/)

