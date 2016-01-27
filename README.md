OpenSwitch HW VTEP (virtual tunnel endpoint)
============================================

What is ops-hw-vtep ?
---------------------
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
The design allows multiple tunneling protocols but initial implementation
targets VXLAN tunnels.
The HW VTEP may run on a real ASIC but it can also execute in simulation
(container plugin) mode.

What is the key component of the repository?
--------------------------------------------
* `vtepd` - A daemon to sync up HW VTEP database to OVSDB and vise-versa.


What is the structure of the repository?
----------------------------------------
* `src` - contains all c source files.
* `include` - contains all c header files.
* `tests` - contains sample python tests.
* `build` - contains cmake build files.

What is the license?
--------------------
Apache 2.0 license. For more details refer to [COPYING](http://www.apache.org/licenses/LICENSE-2.0)

What other documents are available?
-----------------------------------
* [openswitch](http://www.openswitch.net/)
* [OpenvSwitch](http://www.openvswitch.org/)
* [vtep.xml](https://github.com/openvswitch/ovs/blob/master/vtep/vtep.xml)
