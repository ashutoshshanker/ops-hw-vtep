/* Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

#include <stdio.h>
#include <unistd.h>
#include "util.h"
#include "command-line.h"
#include "fatal-signal.h"
#include "vswitch-idl.h"
#include "unixctl.h"
#include "latch.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "dirs.h"
#include "ovsdb-types.h"
#include "vtep-idl.h"
#include "hmap.h"
#include "vtep_ovsdb_if.h"
#include "smap.h"
//#include "hash.h"
//#include "shash.h"

VLOG_DEFINE_THIS_MODULE (vtep_ovsdb_if);

static struct ovsdb_idl *vtep_idl;
static struct ovsdb_idl *ovsdb_idl;

static unsigned int vtep_idl_seqno;
static unsigned int ovsdb_idl_seqno;
static int system_configured = false;

static struct ovsdb_idl_index_cursor cursor_intf;
static struct ovsdb_idl_index_cursor cursor_port;
static struct ovsdb_idl_index_cursor cursor_br;
static struct ovsdb_idl_index_cursor cursor_ovs_mac;
static struct ovsdb_idl_index_cursor cursor_ovs_ls;
static struct ovsdb_idl_index_cursor cursor_vtep_mac;
static struct ovsdb_idl_index_cursor cursor_vtep_physical_locator;
static struct ovsdb_idl_index_cursor cursor_vtep_logical_switch;

static struct hmap all_tunnels;

struct tunnel_node {
    struct hmap_node hmap_node;   /* hmap node */
    char dst_ip[16];
    int tunnel_key;
    char encap[16];
    char ls_name[16];
    int ref_count;
};

static void
insert_logical_switch_config_in_ovsdb(const struct vteprec_logical_switch *
                                 vtep_logical_switch_row,
                                 struct ovsdb_idl *ovsdb_idl,
                                 struct ovsdb_idl_txn *ovs_txn);

static const struct ovsrec_interface *
get_matching_interface_from_ovsdb(const struct vteprec_ucast_macs_remote *vtep_mac_rem_row,
                                  const struct vteprec_physical_locator *vtep_phy_loc_row);

/* Custom comparator for ovsrec_mac_col_tunnel_key */
int ovsdb_idl_index_tunnel_key_cmp(const void *a, const void *b)
{
    struct ovsrec_mac *ovs_mac_a, *ovs_mac_b;
    ovs_mac_a = (struct ovsrec_mac *)a;
    ovs_mac_b = (struct ovsrec_mac *)b;

    return ovsdb_idl_index_intcmp(ovs_mac_a->tunnel_key[0],
                                  ovs_mac_b->tunnel_key[0]);
}

/* Custom comparator for vteprec_physical_locator_col_tunnel_key */
int ovsdb_idl_index_vtep_tunnel_key_cmp(const void *a, const void *b)
{
    struct vteprec_physical_locator *phy_loc_a, *phy_loc_b;
    phy_loc_a = (struct vteprec_physical_locator *)a;
    phy_loc_b = (struct vteprec_physical_locator *)b;

    return ovsdb_idl_index_intcmp(phy_loc_a->tunnel_key[0],
                                  phy_loc_b->tunnel_key[0]);
}

/* Custom comparator for ovsrec_mac_interface_col_options */
int ovsdb_idl_index_intf_options_cmp(const void *a, const void *b)
{
    struct ovsrec_interface *ovs_intf_a, *ovs_intf_b;
    int ret_val = 0;
    ovs_intf_a = (struct ovsrec_interface *)a;
    ovs_intf_b = (struct ovsrec_interface *)b;


    ret_val = ovsdb_idl_index_strcmp((char*)smap_get(&(ovs_intf_a->options),
                                                "remote_ip"),
                                    (char*)smap_get(&(ovs_intf_b->options),
                                                "remote_ip"));
    ret_val = ret_val || ovsdb_idl_index_intcmp(smap_get_int(&(ovs_intf_a->options),
                                                "key", 0),
                                    smap_get_int(&(ovs_intf_b->options),
                                                "key", 0));
    return ret_val;
}

/* Custom comparator for ovsdb_idl_index_bridge_name_cmp */
int ovsdb_idl_index_bridge_name_cmp(const void *a, const void *b)
{
    struct ovsrec_bridge *ovs_br_a, *ovs_br_b;
    int ret_val = 0;
    ovs_br_a = (struct ovsrec_bridge *)a;
    ovs_br_b = (struct ovsrec_bridge *)b;

    return ovsdb_idl_index_strcmp(ovs_br_a->name,
                                  ovs_br_b->name);
}

static void
ovsdb_tables_init()
{
    VLOG_INFO_ONCE("SM: Inside ovsdb tables init");
    struct ovsdb_idl_index *index;

    /* Mac table */
    ovsdb_idl_add_table(ovsdb_idl, &ovsrec_table_mac);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_mac_col_mac_addr);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_mac_col_from);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_mac_col_vlan);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_mac_col_tunnel_key);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_mac_col_bridge);

    /* Track columns from MAC table */
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_mac_col_mac_addr);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_mac_col_from);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_mac_col_vlan);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_mac_col_tunnel_key);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_mac_col_bridge);

    /* Logical switch table */
    ovsdb_idl_add_table(ovsdb_idl, &ovsrec_table_logical_switch);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_logical_switch_col_tunnel_key);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_logical_switch_col_description);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_logical_switch_col_name);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_logical_switch_col_bridge);
    /* Track columns from Logical Switch table */
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_logical_switch_col_tunnel_key);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_logical_switch_col_description);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_logical_switch_col_name);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_logical_switch_col_bridge);

    /* Interface table */
    ovsdb_idl_add_table(ovsdb_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_interface_col_type);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_interface_col_options);
    /* Track columns from Interface table */
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_interface_col_options);

    /* Bridge table*/
    ovsdb_idl_add_table(ovsdb_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_bridge_col_name);

    /* Port table */
    ovsdb_idl_add_table(ovsdb_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovsdb_idl, &ovsrec_port_col_vlan_tunnel_keys);
    /* Track columns from Port table */
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovsdb_idl, &ovsrec_port_col_vlan_tunnel_keys);

    /* Initialize Compound Indexes for mac table*/
    index = ovsdb_idl_create_index(ovsdb_idl, &ovsrec_table_mac,
                                "ovs_mac_by_(mac+from+vlan+bridge+tunnel_key)");
    ovsdb_idl_index_add_column(index, &ovsrec_mac_col_mac_addr,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &ovsrec_mac_col_from,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &ovsrec_mac_col_vlan,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &ovsrec_mac_col_tunnel_key,
                               OVSDB_INDEX_ASC,
                               ovsdb_idl_index_tunnel_key_cmp);
    ovsdb_idl_index_add_column(index, &ovsrec_mac_col_bridge,
                               OVSDB_INDEX_ASC,
                               ovsdb_idl_index_bridge_name_cmp);

    /* Initialize Compound Indexes for logical switch table */
    index = ovsdb_idl_create_index(ovsdb_idl,
                                   &ovsrec_table_logical_switch,
                                   "ovs_logical_switch_by_name");
    ovsdb_idl_index_add_column(index,
                               &ovsrec_logical_switch_col_name,
                               OVSDB_INDEX_ASC, NULL);

    /* Initialize Compound Indexes for port table */
    index = ovsdb_idl_create_index(ovsdb_idl, &ovsrec_table_port,
                                   "ovs_port_by_name");
    ovsdb_idl_index_add_column(index, &ovsrec_port_col_name,
                               OVSDB_INDEX_ASC, NULL);

    /* Initialize Compound Indexes for interface table */
    index = ovsdb_idl_create_index(ovsdb_idl, &ovsrec_table_interface,
                                   "ovs_interface_by_(options+type)");
    ovsdb_idl_index_add_column(index, &ovsrec_interface_col_type,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &ovsrec_interface_col_options,
                               OVSDB_INDEX_ASC,
                               ovsdb_idl_index_intf_options_cmp);

    /* Initialize Compound Indexes for bridge table */
    index = ovsdb_idl_create_index(ovsdb_idl, &ovsrec_table_bridge,
                                   "ovs_bridge_by_name");
    ovsdb_idl_index_add_column(index, &ovsrec_bridge_col_name,
                               OVSDB_INDEX_ASC, NULL);

    VLOG_INFO("SM: Exiting ovsdb_init");
}

static void
vtep_tables_init()
{
    VLOG_INFO_ONCE("SM: Inside vtep tables init");
    struct ovsdb_idl_index *index;

    /* Physical port table */
    ovsdb_idl_add_table(vtep_idl, &vteprec_table_physical_port);
    ovsdb_idl_add_column(vtep_idl, &vteprec_physical_port_col_name);
    ovsdb_idl_add_column(vtep_idl,
                         &vteprec_physical_port_col_port_fault_status);
    ovsdb_idl_add_column(vtep_idl, &vteprec_physical_port_col_vlan_bindings);
    ovsdb_idl_add_column(vtep_idl, &vteprec_physical_port_col_vlan_stats);
    ovsdb_idl_add_column(vtep_idl, &vteprec_physical_port_col_description);
    /* Track columns from physical port table */
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_physical_port_col_name);
    ovsdb_idl_track_add_column(vtep_idl,
                         &vteprec_physical_port_col_port_fault_status);
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_physical_port_col_vlan_bindings);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_physical_port_col_vlan_stats);
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_physical_port_col_description);
    /* Logical switch table */
    ovsdb_idl_add_table(vtep_idl, &vteprec_table_logical_switch);
    ovsdb_idl_add_column(vtep_idl, &vteprec_logical_switch_col_tunnel_key);
    ovsdb_idl_add_column(vtep_idl, &vteprec_logical_switch_col_description);
    ovsdb_idl_add_column(vtep_idl, &vteprec_logical_switch_col_name);
    /* Track columns from logical switch table */
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_logical_switch_col_tunnel_key);
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_logical_switch_col_description);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_logical_switch_col_name);

    /* Ucast macs local table */
    ovsdb_idl_add_table(vtep_idl, &vteprec_table_ucast_macs_local);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_local_col_locator);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_local_col_MAC);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_local_col_ipaddr);
    ovsdb_idl_add_column(vtep_idl,
                         &vteprec_ucast_macs_local_col_logical_switch);
    /* Track columns from ucast macs local table */
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_ucast_macs_local_col_locator);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_ucast_macs_local_col_MAC);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_ucast_macs_local_col_ipaddr);
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_ucast_macs_local_col_logical_switch);

    /* Ucast macs remote table */
    ovsdb_idl_add_table(vtep_idl, &vteprec_table_ucast_macs_remote);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_remote_col_locator);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_remote_col_MAC);
    ovsdb_idl_add_column(vtep_idl, &vteprec_ucast_macs_remote_col_ipaddr);
    ovsdb_idl_add_column(vtep_idl,
                         &vteprec_ucast_macs_remote_col_logical_switch);
    /* Track columns from ucast macs remote table */
    ovsdb_idl_track_add_column(vtep_idl,
                               &vteprec_ucast_macs_remote_col_locator);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_ucast_macs_remote_col_MAC);
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_ucast_macs_remote_col_ipaddr);
    ovsdb_idl_track_add_column(vtep_idl,
                         &vteprec_ucast_macs_remote_col_logical_switch);

    /* Physical locator table*/
    ovsdb_idl_add_table(vtep_idl, &vteprec_table_physical_locator);
    ovsdb_idl_add_column(vtep_idl, &vteprec_physical_locator_col_dst_ip);
    ovsdb_idl_add_column(vtep_idl,
                         &vteprec_physical_locator_col_encapsulation_type);
    /* Track columns from physical locator table*/
    ovsdb_idl_track_add_column(vtep_idl, &vteprec_physical_locator_col_dst_ip);
    ovsdb_idl_track_add_column(vtep_idl,
                         &vteprec_physical_locator_col_encapsulation_type);

    /* Initialize Compound Indexes for ucast_macs_local table */
    index = ovsdb_idl_create_index(vtep_idl,
                                   &vteprec_table_ucast_macs_local,
                                   "vtep_mac_by_mac");
    ovsdb_idl_index_add_column(index, &vteprec_ucast_macs_local_col_MAC,
                               OVSDB_INDEX_ASC, NULL);

    /* Initialize Compound Indexes for physical_locator table */
    index = ovsdb_idl_create_index(vtep_idl,
                                   &vteprec_table_physical_locator,
                                   "vtep_phy_loc_by_(encap+dst_ip)");
    ovsdb_idl_index_add_column(index,
                               &vteprec_physical_locator_col_encapsulation_type,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index,
                               &vteprec_physical_locator_col_dst_ip,
                               OVSDB_INDEX_ASC, NULL);

    /* Initialize Compound Indexes for logical_switch table */
    index = ovsdb_idl_create_index(vtep_idl,
                                   &vteprec_table_logical_switch,
                                   "vtep_ls_by_name");
    ovsdb_idl_index_add_column(index,
                               &vteprec_logical_switch_col_name,
                               OVSDB_INDEX_ASC, NULL);

    VLOG_INFO("SM: Exiting vtep_init");
}

static void
cursor_init_for_compound_index()
{
    ovsdb_idl_initialize_cursor(ovsdb_idl,
                                &ovsrec_table_bridge,
                                "ovs_bridge_by_name",
                                &cursor_br);
    ovsdb_idl_initialize_cursor(ovsdb_idl,
                                &ovsrec_table_interface,
                                "ovs_interface_by_(options+type)",
                                &cursor_intf);
    ovsdb_idl_initialize_cursor(ovsdb_idl,
                                &ovsrec_table_port,
                                "ovs_interface_by_name",
                                &cursor_port);
    ovsdb_idl_initialize_cursor(ovsdb_idl,
                                &ovsrec_table_mac,
                                "ovs_mac_by_(mac+from+vlan+bridge+tunnel_key)",
                                &cursor_ovs_mac);
    ovsdb_idl_initialize_cursor(ovsdb_idl,
                                &ovsrec_table_logical_switch,
                                "ovs_logical_switch_by_name",
                                &cursor_ovs_ls);
    ovsdb_idl_initialize_cursor(vtep_idl,
                                &vteprec_table_ucast_macs_local,
                                "vtep_mac_by_mac",
                                &cursor_vtep_mac);
    ovsdb_idl_initialize_cursor(vtep_idl,
                                &vteprec_table_physical_locator,
                                "vtep_phy_loc_by_(encap+dst_ip)",
                                &cursor_vtep_physical_locator);
    ovsdb_idl_initialize_cursor(vtep_idl,
                                &vteprec_table_logical_switch,
                                "vtep_ls_by_name",
                                &cursor_vtep_logical_switch);
}

/* The init for the vtep integration called in vtep main function. */
void
vtep_ovsdb_init(char *vtep_ovsdb_sock)
{
    VLOG_INFO_ONCE("SM: vtep ovsdb init");
    long int pid;

    pid = getpid();

    VLOG_INFO_ONCE("SM: pid %ld", pid);

    /* Connect to OVS database. */
    ovsdb_idl = ovsdb_idl_create(vtep_ovsdb_sock, &ovsrec_idl_class, false, true);
    VLOG_INFO_ONCE("SM: ovsdb_idl created");
     /* Connect to VTEP database. */
    vtep_idl = ovsdb_idl_create(vtep_ovsdb_sock, &vteprec_idl_class, false, true);
    VLOG_INFO_ONCE("SM: vtep idl created");

    /*
    struct ovsdb_idl_loop vtep_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        vtep_idl);
    VLOG_INFO_ONCE("nitish vtep snapshot");
    ovsdb_idl_get_initial_snapshot(vtep_idl_loop.idl);
    VLOG_INFO_ONCE("nitish got vtep snapshot");
    */


    /*
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl);
    VLOG_INFO_ONCE("nitish ovsdb snapshot");
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);
    VLOG_INFO_ONCE("nitish got ovsdb snapshot");
    */

    ovsdb_idl_seqno = ovsdb_idl_get_seqno(ovsdb_idl);
    ovsdb_idl_set_lock(ovsdb_idl, "ovsdb_lock");
    VLOG_INFO_ONCE("SM: ovsdb_lock set");
    //ovsdb_idl_verify_write_only(ovsdb_idl);

    VLOG_INFO_ONCE("SM: enable ovsdb reconnect");
    ovsdb_idl_enable_reconnect(ovsdb_idl);
    VLOG_INFO_ONCE("SM: ovsdb reconnect enabled");
    vtep_idl_seqno = ovsdb_idl_get_seqno(vtep_idl);

    ovsdb_idl_set_lock(vtep_idl, "vtep_lock");
    VLOG_INFO_ONCE("SM: vtep_lock set");
    //ovsdb_idl_verify_write_only(vtep_idl);

    VLOG_INFO_ONCE("SM: enable vtep reconnect");
    ovsdb_idl_enable_reconnect(vtep_idl);
    VLOG_INFO_ONCE("SM: vtep reconnect enabled");

    /* Ovsdb table initialization */
    ovsdb_tables_init();
    VLOG_INFO_ONCE("SM: ovsdb table initialized");
    /* Vtep table initialization */
    vtep_tables_init();
    VLOG_INFO_ONCE("SM: vtep table initialized");

    hmap_init(&all_tunnels);

    /* Initialize cursor for compound indexes */
    cursor_init_for_compound_index();

    VLOG_INFO_ONCE("OPS Vtep OVSDB Integration has been initialized");

    return;
}

static uint32_t
convert_ip_int(const char *ip)
{
    unsigned int ipbytes[4];

    sscanf(ip, "%u.%u.%u.%u", &ipbytes[3], &ipbytes[2], &ipbytes[1], &ipbytes[0]);
    return (ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24);
}

static uint32_t
calculate_hash_tunnel(uint32_t ip, int64_t tunnel_key)
{
    return (hash_2words(hash_uint64_basis(tunnel_key, 0), ip));
}

static void
bridge_insert_port(const struct ovsrec_bridge *br, const struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i;

    ports = xmalloc(sizeof *br->ports * (br->n_ports + 1));
    for (i = 0; i < br->n_ports; i++) {
        ports[i] = br->ports[i];
    }
    ports[br->n_ports] = (struct ovsrec_port *)port;
    ovsrec_bridge_set_ports(br, ports, br->n_ports + 1);
    free(ports);
}

static void
bridge_delete_port(const struct ovsrec_bridge *br, const struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i, n;

    ports = xmalloc(sizeof *br->ports * br->n_ports);
    for (i = n = 0; i < br->n_ports; i++) {
        if (br->ports[i] != port) {
            ports[n++] = br->ports[i];
        }
    }
    ovsrec_bridge_set_ports(br, ports, n);
    free(ports);
}

static void
vtep_create_tunnel(const struct vteprec_ucast_macs_remote *vtep_mac_rem_row,
                   const struct ovsrec_bridge *bridge_e,
                   unsigned int *tunnel_id)
{
    const struct ovsrec_interface *interface_e = NULL;
    const struct ovsrec_port *port_e = NULL;
    struct ovsrec_interface value_intf;
    struct ovsdb_idl_txn *tunnel_txn;
    struct tunnel_node *node = NULL;
    char *encap_type = NULL;
    int64_t tunnel_key = -1;
    char intf_name[16] = {0};
    struct ovsrec_port value_port;
    struct smap options = SMAP_INITIALIZER(&options);
    uint32_t hash = 0;
    char *dst_ip = NULL;
    bool found = false;
    bool has_ls = false;
    const char *ls_name = NULL;
    char buf[9];

    if (!tunnel_txn) {
        tunnel_txn = ovsdb_idl_txn_create(ovsdb_idl);
        if (!tunnel_txn) {
            VLOG_ERR("Unable to create transaction");
            return;
        }
    }

    if(vtep_mac_rem_row->locator) {
        encap_type = vtep_mac_rem_row->locator->encapsulation_type;
        dst_ip = vtep_mac_rem_row->locator->dst_ip;

        if(vtep_mac_rem_row->locator->tunnel_key)
            tunnel_key = *vtep_mac_rem_row->locator->tunnel_key;
        else if (vtep_mac_rem_row->logical_switch->tunnel_key) {
            tunnel_key = *vtep_mac_rem_row->logical_switch->tunnel_key;
            has_ls = true;
        } else {
            VLOG_ERR("%s: Tunnel cannot be created/deleted/modified as "
                     "either logical_switch or locator->tunnel_key is "
                     "requried", __FUNCTION__);
            return;
        }
    }
    if (!dst_ip || (tunnel_key == -1) ||
        strcmp(encap_type, "vxlan_over_ipv4")) {
        VLOG_ERR("%s: tunnel params not correctly defined", __FUNCTION__);
        return;
    }

    hash = calculate_hash_tunnel(convert_ip_int(dst_ip), tunnel_key);

    /*
     * find if the tunnel exists
     */

    interface_e = get_matching_interface_from_ovsdb(vtep_mac_rem_row, NULL);
    /*
    * ideally this should only be one
    */
    if (has_ls) {
        /*
         * check logical switch name
         */
        ls_name = smap_get(&(interface_e->other_config), "logical_switch_name");
        if (ls_name) {
            if (strcmp(ls_name, vtep_mac_rem_row->logical_switch->name)) {
                VLOG_DBG("logical switch %s found\n", ls_name);
            }
        }
    }

    //record points to the interface to be deleted, same with the port as well
    value_port.name = interface_e->name;
    OVSREC_PORT_FOR_EACH_EQUAL(port_e, &cursor_port, &value_port) {
        /*
         * this will only be one as the port name is the index in the schema
         */
        found = true;

        // hmap_get and increment the refcount
        HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, &all_tunnels) {
            if ((node->tunnel_key == tunnel_key) &&
                !(strcmp(node->dst_ip, dst_ip))) {
                if (has_ls) {
                    if (!strcmp(node->ls_name, ls_name)) {
                        node->ref_count++;
                    }
                } else {
                    node->ref_count++;
                }
            }
        }
    }

    if (!found) {
        port_e = ovsrec_port_insert(tunnel_txn);
        interface_e = ovsrec_interface_insert(tunnel_txn);
        strcpy(intf_name, "_tunnel_");
        (*tunnel_id)++;
        sprintf(buf, "%d", *tunnel_id);
        strcat(intf_name, buf);
        ovsrec_interface_set_name(interface_e, intf_name);

        ovsrec_interface_set_type(interface_e, "vxlan");
//        options = SMAP_INITIALIZER(&options);
        smap_add(&options, "remote_ip", dst_ip);
//        buf = NULL;
        sprintf(buf, "%d", tunnel_key);
        smap_add(&options, "key", buf);
        ovsrec_interface_set_options(interface_e, &options);
//        smap_destroy(&options);
        smap_clear(&options);
        hmap_destroy(&options.map);

        if (has_ls) {
//            options = SMAP_INITIALIZER(&options);
            smap_add(&options, "logical_switch_name", vtep_mac_rem_row->logical_switch->name);
            ovsrec_interface_set_other_config(interface_e, &options);
            smap_destroy(&options);
        }

        ovsrec_port_set_name((const struct ovsrec_port*)port_e, intf_name);
        ovsrec_port_set_interfaces((const struct ovsrec_port*)port_e,
                                   (struct ovsrec_interface **)&interface_e,
                                   1);
        bridge_insert_port(bridge_e, port_e);

        node = xmalloc(sizeof (*node));
        hmap_insert(&all_tunnels, &node->hmap_node, hash);
        strncpy(node->dst_ip, dst_ip, sizeof(dst_ip));
        node->tunnel_key = tunnel_key;
        strcpy(node->encap, "vxlan");
        node->ref_count = 1;
    }
}

static void
vtep_delete_tunnel(const struct vteprec_ucast_macs_remote *vtep_mac_rem_row,
                   const struct ovsrec_bridge *bridge_e)
{
    const struct ovsrec_interface *interface_e = NULL;
    const struct ovsrec_port *port_e = NULL;
    struct ovsrec_interface value_intf;
    struct ovsdb_idl_txn *tunnel_txn;
    enum ovsdb_idl_txn_status status;
    char *encap_type = NULL;
    struct tunnel_node *node = NULL;
    int64_t tunnel_key = -1;
    struct ovsrec_port value_port;
    uint32_t hash = 0;
    char *dst_ip = NULL;
    struct smap options;
    bool found = false;
    bool has_ls = false;
    char *ls_name = NULL;

    if (!tunnel_txn) {
        tunnel_txn = ovsdb_idl_txn_create(ovsdb_idl);
        if (!tunnel_txn) {
            VLOG_ERR("Transaction create failed");
            return;
        }
    }

    if (vtep_mac_rem_row->locator) {
        encap_type = vtep_mac_rem_row->locator->encapsulation_type;
        dst_ip = vtep_mac_rem_row->locator->dst_ip;
        if (vtep_mac_rem_row->locator->tunnel_key)
            tunnel_key = *vtep_mac_rem_row->locator->tunnel_key;
        else if (vtep_mac_rem_row->logical_switch->tunnel_key) {
            tunnel_key = *vtep_mac_rem_row->logical_switch->tunnel_key;
            has_ls = true;
        } else
            VLOG_ERR("%s: Tunnel cannot be created/deleted/modified as "
                     "either logical_switch or locator->tunnel_key is "
                     "requried", __FUNCTION__);
            return;
    }

    if (!dst_ip || (tunnel_key == -1) ||
        strcmp(encap_type, "vxlan_over_ipv4")) {
        VLOG_ERR("%s: tunnel params not correctly defined", __FUNCTION__);
        return;
    }

    /*
     * find record by value for interface
     */

    hash = calculate_hash_tunnel(convert_ip_int(dst_ip), tunnel_key);

    interface_e = get_matching_interface_from_ovsdb(vtep_mac_rem_row, NULL);

    //record points to the interface to be deleted, same with the port as well
    value_port.name = interface_e->name;
    OVSREC_PORT_FOR_EACH_EQUAL(port_e, &cursor_port, &value_port) {

    /*
     * this will only be one as the port name is the index in the schema
     */
    /*
     * decrement the refcount, if 0, delete the hmap node
     */
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, &all_tunnels) {
        if ((node->tunnel_key == tunnel_key) &&
            !(strcmp(node->dst_ip, dst_ip))) {
                if (has_ls && !strcmp(node->ls_name, ls_name)) {
                    found = true;
                }
                if (found || !has_ls) {
                    if (node->ref_count > 1) {
                        node->ref_count--;
                    } else {
                        hmap_remove(&all_tunnels, &node->hmap_node);
                        free(node);
                        ovsrec_interface_delete(interface_e);
                        ovsrec_port_delete(port_e);
                        bridge_delete_port(bridge_e, port_e);
                    }
                }
            }
        }
    }
    status = ovsdb_idl_txn_commit_block(tunnel_txn);
    ovsdb_idl_txn_destroy(tunnel_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
}

static void
delete_mac_config_from_vtep(const struct vteprec_ucast_macs_local *vtep_mac_row,
                            struct ovsdb_idl *vtep_idl)
{
    struct ovsdb_idl_txn *vtep_txn;
    enum ovsdb_idl_txn_status status;

    vtep_txn = ovsdb_idl_txn_create(vtep_idl);
    if (!vtep_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    vteprec_ucast_macs_local_delete(vtep_mac_row);
    VLOG_INFO("Mac deleted from vtep");
    status = ovsdb_idl_txn_commit_block(vtep_txn);
    ovsdb_idl_txn_destroy(vtep_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
update_mac_config_in_vtep(const struct vteprec_ucast_macs_local *vtep_mac_row,
                          const struct ovsrec_mac *ovs_mac_row,
                          struct ovsdb_idl *vtep_idl)
{
    struct ovsdb_idl_txn *vtep_txn;
    enum ovsdb_idl_txn_status status;
    const char *mac_addr;

    if(strcmp(ovs_mac_row->from, "dynamic") == 0)
    {
        mac_addr = ovs_mac_row->mac_addr;
        vtep_txn = ovsdb_idl_txn_create(vtep_idl);
        if (!vtep_txn)
        {
            VLOG_DBG ("Transaction create failed");
            return;
        }
        vteprec_ucast_macs_local_set_MAC(vtep_mac_row, mac_addr);
        VLOG_INFO("Mac updated in vtep");
        status = ovsdb_idl_txn_commit_block(vtep_txn);
        ovsdb_idl_txn_destroy(vtep_txn);
        VLOG_DBG("txn result: %s\n",
                 ovsdb_idl_txn_status_to_string(status));
    }
}

static void
check_physical_locator_config_in_vtep(
                        const struct ovsrec_mac *ovs_mac_row,
                        const struct vteprec_ucast_macs_local *vtep_mac_row,
                        struct ovsdb_idl_txn *vtep_txn,
                        const struct ovsdb_idl *vtep_idl)
{
    const struct vteprec_physical_switch *vtep_phy_switch_row = NULL;
    const struct vteprec_physical_locator *vtep_phy_loc_row = NULL;
    struct vteprec_physical_locator value_phy_loc;
    char *remote_ip = NULL;
    int i = 0;

    /* Read the tunnel_ips from physical switch table */
    vtep_phy_switch_row = vteprec_physical_switch_first(vtep_idl);

    vtep_phy_loc_row =  vteprec_physical_locator_first(vtep_idl);

    if(vtep_phy_loc_row == NULL)
    {
        /* Create row per tunnel_ip in physical locator */
        for (i = 0; i < vtep_phy_switch_row->n_tunnel_ips; i++)
        {
            vtep_phy_loc_row = vteprec_physical_locator_insert(vtep_txn);
            vteprec_ucast_macs_local_set_locator(vtep_mac_row, vtep_phy_loc_row);
            vteprec_physical_locator_set_encapsulation_type(vtep_phy_loc_row,
                                                             "vxlan_over_ipv4");
            vteprec_physical_locator_set_dst_ip(vtep_phy_loc_row,
                                                vtep_phy_switch_row->tunnel_ips[i]);
            vtep_phy_loc_row = NULL;
        }
    }
    else {

        value_phy_loc.encapsulation_type = "vxlan_over_ipv4";
        remote_ip = (char*)smap_get(&(ovs_mac_row->port->interfaces[0]->options),
                            "remote_ip");
        value_phy_loc.dst_ip = remote_ip;

        VTEPREC_PHYSICAL_LOCATOR_FOR_EACH_EQUAL(vtep_phy_loc_row,
                                                &cursor_vtep_physical_locator,
                                                &value_phy_loc)

        if (strcmp(vtep_phy_loc_row->dst_ip, remote_ip) == 0) {
            /* Add a reference in Ucast_Macs_Local table for locator */
            vteprec_ucast_macs_local_set_locator(vtep_mac_row, vtep_phy_loc_row);
        }
        else {
            VLOG_ERR("%s: vtep physical locator not found", __FUNCTION__);
        }
    }
}

static void
check_logical_switch_config_in_vtep(
                        const struct vteprec_ucast_macs_local *vtep_mac_row,
                        int vtep_tunnel_key,
                        struct ovsdb_idl *vtep_idl)
{
    const struct vteprec_logical_switch *vtep_ls_row = NULL;
    bool found = false;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH(vtep_ls_row, vtep_idl) {
        if (vtep_ls_row->tunnel_key[0] == vtep_tunnel_key)
        {
            found = true;
            break;
        }
    }

    if(found)
    {
        VLOG_INFO("Given tunnel key already exists...");
        /* Add a reference for logical switch in Ucast_Macs_Local table */
        vteprec_ucast_macs_local_set_logical_switch(vtep_mac_row, vtep_ls_row);
    }
    else {
        VLOG_ERR("Tunnel key %d not found in vtep", vtep_tunnel_key);
    }
    return;
}

static void
insert_mac_config_in_vtep(const struct ovsrec_mac *ovs_mac_row,
                          struct ovsdb_idl *vtep_idl)
{
    const struct vteprec_ucast_macs_local *vtep_mac_row = NULL;
    const struct ovsrec_logical_switch *ovs_ls_row = NULL;
    int vtep_tunnel_key, i;
    struct ovsdb_idl_txn *vtep_txn;
    enum ovsdb_idl_txn_status status;
    const char *mac_addr;
    bool set_mac_in_vtep = false;

    VLOG_INFO("SM: Inside insert_mac_config_in_vtep");
    mac_addr = ovs_mac_row->mac_addr;
    VLOG_INFO("SM: mac_addr = %s", mac_addr);

    /* Check if we have to create an entry in vtep */
    if (ovs_mac_row->port->interfaces[0]->type == "vxlan") {
        VLOG_INFO("SM: Create an entry in ucast_macs_local");
        set_mac_in_vtep = true;
    }
    else {
        if (ovs_mac_row->port->n_vlan_tunnel_keys > 0 )
        {
            for(i = 0; i < ovs_mac_row->port->n_vlan_tunnel_keys; i++)
            {
                if(ovs_mac_row->vlan == ovs_mac_row->port->key_vlan_tunnel_keys[i])
                {
                    ovs_ls_row = ovs_mac_row->port->value_vlan_tunnel_keys[i];
                    vtep_tunnel_key = ovs_ls_row->tunnel_key;
                    set_mac_in_vtep = true;
                }
            }
        }
    }

    if (set_mac_in_vtep)
    {
        vtep_txn = ovsdb_idl_txn_create(vtep_idl);
        if (!vtep_txn)
        {
            VLOG_DBG ("Transaction create failed");
            return;
        }

        vtep_mac_row = vteprec_ucast_macs_local_insert(vtep_txn);
        vteprec_ucast_macs_local_set_MAC(vtep_mac_row, mac_addr);

        /* Insert a new physical locator */
        check_physical_locator_config_in_vtep(ovs_mac_row, vtep_mac_row, vtep_txn, vtep_idl);

        /* Check a logical switch */
        check_logical_switch_config_in_vtep(vtep_mac_row, vtep_tunnel_key,
                                             vtep_idl);

        VLOG_INFO("Mac inserted in vtep");
        status = ovsdb_idl_txn_commit_block(vtep_txn);
        ovsdb_idl_txn_destroy(vtep_txn);
        VLOG_INFO("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    }
}

static void
delete_mac_config_from_ovsdb(const struct ovsrec_mac *ovs_mac_row,
                             struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovsrec_mac_delete(ovs_mac_row);
    VLOG_INFO("Mac deleted from ovsdb");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
update_mac_config_in_ovsdb(const struct ovsrec_mac *ovs_mac_row,
                           const struct vteprec_ucast_macs_remote *vtep_mac_row,
                           struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;
    const char *mac_addr;

    mac_addr = vtep_mac_row->MAC;
    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovsrec_mac_set_mac_addr(ovs_mac_row, mac_addr);
    VLOG_INFO("Mac updated in ovsdb");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
insert_mac_config_in_ovsdb(const struct vteprec_ucast_macs_remote *vtep_mac_row,
                           struct ovsdb_idl *ovsdb_idl)
{
    const struct ovsrec_mac *ovs_mac_row = NULL;
    struct ovsrec_logical_switch *ovs_ls_row = NULL;
    struct vteprec_logical_switch *vtep_ls_row = NULL;
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;
    char *ls_name;
    const char *mac_addr;

    mac_addr = vtep_mac_row->MAC;
    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    /* Insert a row in MAC table in OVSDB */
    ovs_mac_row = ovsrec_mac_insert(ovs_txn);

    /* Add a reference to Logical Switch */
    vtep_ls_row = vtep_mac_row->logical_switch;
    insert_logical_switch_config_in_ovsdb(vtep_ls_row, ovsdb_idl, ovs_txn);

    ovsrec_mac_set_mac_addr(ovs_mac_row, mac_addr);
    ovsrec_mac_set_from(ovs_mac_row, "hw-vtep");
    VLOG_INFO("Mac inserted in ovsdb");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
delete_port_config_from_ovsdb(const struct ovsrec_port *ovs_port_row,
                              struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovsrec_port_delete(ovs_port_row);
    VLOG_INFO("Port deleted from ovsdb");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
update_port_config_in_ovsdb(const struct ovsrec_port *ovs_port_row,
                            const struct vteprec_physical_port *
                                vtep_physical_port_row,
                            struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;
    int i, j, ii, jj;
    bool found = false;
    int64_t *vlan_id_list;
    struct ovsrec_logical_switch **logical_switch_list;
    struct ovsrec_logical_switch *ovs_logical_switch_row = NULL;
    int64_t vlan_id;
    unsigned int n_vlan_binding_keys, n_vlan_tunnel_keys;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }

    n_vlan_binding_keys = vtep_physical_port_row->n_vlan_bindings;
    n_vlan_tunnel_keys = ovs_port_row->n_vlan_tunnel_keys;

    if(n_vlan_binding_keys > n_vlan_tunnel_keys)
    {
        VLOG_DBG("Vlan tunnel key insertion\n");
        for (i = 0; i < vtep_physical_port_row->n_vlan_bindings; i++) {
            found = false;
            for (j = 0; j < ovs_port_row->n_vlan_tunnel_keys; j++) {
                if(vtep_physical_port_row->key_vlan_bindings[i] ==
                   ovs_port_row->key_vlan_tunnel_keys[j])
                {
                    found = true;
                    break;
                }
                else
                    vlan_id = vtep_physical_port_row->key_vlan_bindings[i];
            }
            if(!found)
            {
                /* Insert a new row in Logical Switch Table */
                ovs_logical_switch_row = ovsrec_logical_switch_insert(ovs_txn);

                /* Insert Logical_Switch table reference in Port table. */
                vlan_id_list = xmalloc(sizeof(int64_t) *
                    (ovs_port_row->n_vlan_tunnel_keys + 1));
                logical_switch_list = xmalloc(sizeof *
                    ovs_port_row->value_vlan_tunnel_keys *
                    (ovs_port_row->n_vlan_tunnel_keys + 1));

                for (ii = 0; ii < ovs_port_row->n_vlan_tunnel_keys; ii++) {
                    vlan_id_list[ii] = ovs_port_row->key_vlan_tunnel_keys[ii];
                    logical_switch_list[ii] =
                        ovs_port_row->value_vlan_tunnel_keys[ii];
                }
                vlan_id_list[ovs_port_row->n_vlan_tunnel_keys] = vlan_id;
                logical_switch_list[ovs_port_row->n_vlan_tunnel_keys] =
                     CONST_CAST(struct ovsrec_logical_switch *, ovs_logical_switch_row);
                ovsrec_port_set_vlan_tunnel_keys(ovs_port_row, vlan_id_list,
                    logical_switch_list, (ovs_port_row->n_vlan_tunnel_keys + 1));
                free(vlan_id_list);
                free(logical_switch_list);
            }
        }
    }
    else {
        VLOG_DBG("Vlan tunnel key deletion\n");

        for (i = 0; i < ovs_port_row->n_vlan_tunnel_keys; i++) {
            found = false;
            for (j = 0; j < vtep_physical_port_row->n_vlan_bindings; j++) {
                if(ovs_port_row->key_vlan_tunnel_keys[i] ==
                    vtep_physical_port_row->key_vlan_bindings[j])
                {
                    found = true;
                    break;
                }
                else
                {
                    vlan_id = ovs_port_row->key_vlan_tunnel_keys[i];
                    ovs_logical_switch_row =
                        ovs_port_row->value_vlan_tunnel_keys[i];
                }
            }
            if (!found)
            {
                /* Insert Logical_Switch table reference in Port table. */
                vlan_id_list = xmalloc(sizeof(int64_t) *
                    (ovs_port_row->n_vlan_tunnel_keys - 1));
                logical_switch_list = xmalloc(sizeof *
                    ovs_port_row->value_vlan_tunnel_keys *
                    (ovs_port_row->n_vlan_tunnel_keys - 1));

                for (ii = 0, jj = 0; ii < ovs_port_row->n_vlan_tunnel_keys;
                    ii++) {
                    if (ovs_port_row->key_vlan_tunnel_keys[ii] != vlan_id)
                    {
                        vlan_id_list[jj] =
                            ovs_port_row->key_vlan_tunnel_keys[ii];
                        logical_switch_list[jj] =
                            ovs_port_row->value_vlan_tunnel_keys[ii];
                        jj++;
                    }
                }
                ovsrec_port_set_vlan_tunnel_keys(ovs_port_row, vlan_id_list,
                    logical_switch_list, (ovs_port_row->n_vlan_tunnel_keys - 1));
                /* Delete a row from Logical Switch Table */
                ovsrec_logical_switch_delete(ovs_logical_switch_row);
                free(vlan_id_list);
                free(logical_switch_list);
            }
        }
    }


    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
}

static void
insert_port_config_in_ovsdb(const struct vteprec_physical_port *
                            vtep_physical_port_row,
                            struct ovsdb_idl *ovsdb_idl)
{
    struct ovsrec_port *ovs_port_row = NULL;
    struct ovsrec_logical_switch *ovs_logical_switch_row = NULL;
    int64_t *vlan_id_list;
    struct ovsrec_logical_switch **logical_switch_list;
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;
    int i, j;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    /* Insert a new row in Port Table */
    ovs_port_row = ovsrec_port_insert(ovs_txn);
    /* Set the name column in Port Table */
    ovsrec_port_set_name(ovs_port_row, vtep_physical_port_row->name);

    vlan_id_list = xmalloc(sizeof(int64_t) *
        vtep_physical_port_row->n_vlan_bindings);
    logical_switch_list = xmalloc(sizeof *
        (vtep_physical_port_row->value_vlan_bindings) *
        vtep_physical_port_row->n_vlan_bindings);

    /* Create the logical switch rows for given vlan ids in ovsdb */
    for (i = 0, j = 0; i < vtep_physical_port_row->n_vlan_bindings; i++) {
        vlan_id_list[j] = vtep_physical_port_row->key_vlan_bindings[i];
        ovs_logical_switch_row = ovsrec_logical_switch_insert(ovs_txn);
        logical_switch_list[j] = CONST_CAST(struct ovsrec_logical_switch *,
                                            ovs_logical_switch_row);
        j++;
        ovs_logical_switch_row = NULL;
    }

    /* Insert Logical_Switch table reference in Port table. */
    ovsrec_port_set_vlan_tunnel_keys(ovs_port_row, vlan_id_list,
        logical_switch_list, vtep_physical_port_row->n_vlan_bindings);
    free(vlan_id_list);
    free(logical_switch_list);

    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
}

static void
delete_interface_config_from_ovsdb(const struct ovsrec_interface *
                                   ovs_interface_row,
                                   struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovsrec_interface_delete(ovs_interface_row);
    VLOG_INFO("Interface deleted");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
update_interface_config_in_ovsdb(const struct ovsrec_interface *
                                 ovs_interface_row,
                                 const struct vteprec_physical_locator *
                                 vtep_physical_locator_row,
                                 struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    /* add remote_ip and VNI (key, value) */
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
}

static void
insert_interface_config_in_ovsdb(const struct vteprec_physical_locator *
                                 vtep_physical_locator_row,
                                 struct ovsdb_idl *ovsdb_idl)
{
    const struct ovsrec_interface *ovs_interface_row = NULL;
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;
    const char *encap_type;

    encap_type = vtep_physical_locator_row->encapsulation_type;
    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovs_interface_row = ovsrec_interface_insert(ovs_txn);
    ovsrec_interface_set_type(ovs_interface_row, encap_type);
    /* add remote_ip and VNI (key, value) */
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n",
             ovsdb_idl_txn_status_to_string(status));
}

static void
delete_logical_switch_config_from_ovsdb(const struct ovsrec_logical_switch *
                                      ovs_logical_switch_row,
                                      struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    ovsrec_logical_switch_delete(ovs_logical_switch_row);
    VLOG_INFO("Logical switch deleted");
    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    return;
}

static void
update_logical_switch_config_in_ovsdb(const struct ovsrec_logical_switch *
                                 ovs_logical_switch_row,
                                 const struct vteprec_logical_switch *
                                 vtep_logical_switch_row,
                                 struct ovsdb_idl *ovsdb_idl)
{
    struct ovsdb_idl_txn *ovs_txn;
    enum ovsdb_idl_txn_status status;

    ovs_txn = ovsdb_idl_txn_create(ovsdb_idl);
    if (!ovs_txn)
    {
        VLOG_DBG ("Transaction create failed");
        return;
    }
    if(strcmp(vtep_logical_switch_row->description,
              ovs_logical_switch_row->description) != 0)
        ovsrec_logical_switch_set_description(ovs_logical_switch_row,
                                          vtep_logical_switch_row->description);

    if(vtep_logical_switch_row->tunnel_key[0] !=
       ovs_logical_switch_row->tunnel_key)
        ovsrec_logical_switch_set_tunnel_key(ovs_logical_switch_row,
                                        vtep_logical_switch_row->tunnel_key[0]);

    status = ovsdb_idl_txn_commit_block(ovs_txn);
    ovsdb_idl_txn_destroy(ovs_txn);
    VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
}


static void
insert_logical_switch_config_in_ovsdb_(
                const struct vteprec_logical_switch *vtep_logical_switch_row,
                struct ovsdb_idl *ovsdb_idl,
                struct ovsdb_idl_txn *ovs_txn)
{
    const struct ovsrec_logical_switch *ovs_logical_switch_row = NULL;

    ovs_logical_switch_row = ovsrec_logical_switch_insert(ovs_txn);
    ovsrec_logical_switch_set_name(ovs_logical_switch_row,
                                   vtep_logical_switch_row->name);
    ovsrec_logical_switch_set_description(ovs_logical_switch_row,
                                       vtep_logical_switch_row->description);
    ovsrec_logical_switch_set_tunnel_key(ovs_logical_switch_row,
                                        vtep_logical_switch_row->tunnel_key[0]);
}
static void
insert_logical_switch_config_in_ovsdb(
                const struct vteprec_logical_switch *vtep_ls_row,
                struct ovsdb_idl *ovsdb_idl,
                struct ovsdb_idl_txn *ovs_txn)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;

    if(ovs_txn == NULL)
    {
        txn = ovsdb_idl_txn_create(ovsdb_idl);
        if (!txn)
        {
            VLOG_DBG ("Transaction create failed");
            return;
        }

        insert_logical_switch_config_in_ovsdb_(vtep_ls_row, ovsdb_idl, txn);

        status = ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
        VLOG_DBG("txn result: %s\n", ovsdb_idl_txn_status_to_string(status));
    }
    else
        insert_logical_switch_config_in_ovsdb_(vtep_ls_row, ovsdb_idl, ovs_txn);

    VLOG_INFO("Logical Switch Inserted in OVSDB");
}

static struct vteprec_ucast_macs_local *
get_matching_physical_locator_from_vtep(const struct ovsrec_mac *ovs_mac_row,
                            struct vteprec_ucast_macs_local **ucast_macs_list,
                            int num_of_matching_macs)
{
    const struct vteprec_physical_locator *phy_loc = NULL;
    struct vteprec_physical_locator value_phy_loc;
    char *encap = "vxlan_over_ipv4";
    char ip[16] = {0};
    int i = 0;

    value_phy_loc.encapsulation_type = encap;
    value_phy_loc.dst_ip = ip;
    strncpy(value_phy_loc.dst_ip, (char*)smap_get(
                                &(ovs_mac_row->port->interfaces[0]->options),
                                "remote_ip"), 15);

    VTEPREC_PHYSICAL_LOCATOR_FOR_EACH_EQUAL(phy_loc,
                                &cursor_vtep_physical_locator, &value_phy_loc) {
        VLOG_DBG("vtep mac found");
        for (i = 0; i < num_of_matching_macs; i++) {
            if (phy_loc->encapsulation_type ==
                    ucast_macs_list[i]->locator->encapsulation_type &&
                phy_loc->dst_ip == ucast_macs_list[i]->locator->dst_ip) {
                    VLOG_DBG("vtep physical locator found");
                    return ucast_macs_list[i];
                }
        }
        VLOG_ERR("%s: vtep physical locator not found", __FUNCTION__);
    }
}

static struct vteprec_ucast_macs_local *
get_matching_logical_switch_from_vtep(const struct ovsrec_mac *ovs_mac_row,
                                    struct vteprec_ucast_macs_local **ucast_macs_list,
                                    int num_of_matching_macs)
{
    const struct vteprec_logical_switch *ls = NULL;
    struct vteprec_logical_switch value_ls;
    int i = 0;

    value_ls.name = ovs_mac_row->port->value_vlan_tunnel_keys[0]->name;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH_EQUAL(ls,
                                &cursor_vtep_logical_switch, &value_ls) {
        for (i = 0; i < num_of_matching_macs; i++) {
            if (ls->name == ucast_macs_list[i]->logical_switch->name) {
                    VLOG_DBG("vtep logical switch found");
                    return ucast_macs_list[i];
                }
        }
        VLOG_ERR("%s: vtep logical switch not found", __FUNCTION__);
    }
}

static struct vteprec_ucast_macs_local *
get_matching_mac_from_vtep(const struct ovsrec_mac *ovs_mac_row)
{
    const struct vteprec_ucast_macs_local *ucast_mac;
    struct vteprec_ucast_macs_local value_mac;
    struct vteprec_ucast_macs_local **ucast_macs_list;
    struct vteprec_physical_locator *phy_loc = NULL;
    struct vteprec_logical_switch *ls = NULL;

    int num_of_matching_macs = 0;

    /* Find the record matching given index */
    value_mac.MAC = ovs_mac_row->mac_addr;

    VTEPREC_UCAST_MACS_LOCAL_FOR_EACH_EQUAL(ucast_mac, &cursor_vtep_mac,
                                            &value_mac) {
        /* Can return zero, one or more records */
        ucast_macs_list[num_of_matching_macs] = (struct vteprec_ucast_macs_local *)ucast_mac;
        ucast_mac = NULL;
        num_of_matching_macs++;
    }

    if (get_matching_physical_locator_from_vtep(ovs_mac_row,
                                                ucast_macs_list,
                                                num_of_matching_macs)
                                                ==
        get_matching_logical_switch_from_vtep(ovs_mac_row,
                                              ucast_macs_list,
                                              num_of_matching_macs)) {
        VLOG_DBG("vtep mac found");
        return get_matching_logical_switch_from_vtep(ovs_mac_row,
                                              ucast_macs_list,
                                              num_of_matching_macs);
    }
    else {
        VLOG_ERR("%s: No matching mac found for deletion or modification\n",
                __FUNCTION__);
    }
}

static const struct ovsrec_mac *
get_matching_mac_from_ovsdb(const struct vteprec_ucast_macs_remote *ucast_mac_remote_row)
{
    const struct ovsrec_mac *ovs_mac_row;
    struct ovsrec_mac value_mac;
    const struct vteprec_physical_locator *physical_loc_row;
    const struct ovsdb_idl_row *ovs_row;
    struct ovsdb_idl_table_class *table;
    int64_t vtep_tunnel_key;
    char *from = "hw-vtep";

    ovs_row = ovsdb_idl_get_row_for_uuid(vtep_idl, table,
                (const struct uuid *) ucast_mac_remote_row->locator);

    physical_loc_row = (struct vteprec_physical_locator *) ovs_row;
    value_mac.from = from;
//    strcpy(value_mac.from, "hw-vtep");
    value_mac.mac_addr = ucast_mac_remote_row->MAC;
    value_mac.tunnel_key = &physical_loc_row->tunnel_key[0];

    OVSREC_MAC_FOR_EACH_EQUAL(ovs_mac_row, &cursor_ovs_mac, &value_mac) {
        /* Can return zero, one or more records */
        VLOG_DBG("ovsdb mac found");
        return ovs_mac_row;
    }
}

static const struct ovsrec_port *
get_matching_port_from_ovsdb(const struct vteprec_physical_port *vtep_physical_port_row)
{
    const struct ovsrec_port *ovs_port_row;
    struct ovsrec_port value_port;

    value_port.name = vtep_physical_port_row->name;
    OVSREC_PORT_FOR_EACH_EQUAL(ovs_port_row, &cursor_port, &value_port) {
        /* Can return zero, one or more records */
        VLOG_DBG("ovsdb port found");
        return ovs_port_row;
    }
}

static const struct ovsrec_bridge *
get_matching_bridge_from_ovsdb()
{
    /*
     * Currently, we support single bridge "bridge_normal", needs to be changed
     * later when multiple bridges are supported.
     */
    const struct ovsrec_bridge *ovs_br;
    struct ovsrec_bridge value_br;
    value_br.name = "bridge_normal";
    OVSREC_BRIDGE_FOR_EACH_EQUAL(ovs_br, &cursor_br, &value_br) {
        VLOG_DBG("ovsdb bridge found");
        return ovs_br;
    }

    if (!ovs_br) {
        VLOG_ERR("%s: bridge not found", __FUNCTION__);
        return NULL;
    }
}

static const struct ovsrec_interface *
get_matching_interface_from_ovsdb(const struct vteprec_ucast_macs_remote *vtep_mac_rem_row,
                                  const struct vteprec_physical_locator *vtep_phy_loc_row)
{
    const struct ovsrec_interface *intf_row;
    struct ovsrec_interface value_intf;
    char *dst_ip = NULL;
    char *encap_type = NULL;
    int64_t tunnel_key = -1;
    struct smap options;
    char buf[9] = {0};

    if (vtep_mac_rem_row && vtep_mac_rem_row->locator) {
        encap_type = vtep_mac_rem_row->locator->encapsulation_type;
        dst_ip = vtep_mac_rem_row->locator->dst_ip;
        if (vtep_mac_rem_row->locator->tunnel_key)
            tunnel_key = *vtep_mac_rem_row->locator->tunnel_key;
        else if (vtep_mac_rem_row->logical_switch->tunnel_key)
            tunnel_key = *vtep_mac_rem_row->logical_switch->tunnel_key;
        else {
            VLOG_ERR("%s: Tunnel cannot be created/deleted/modified as "
                     "either logical_switch or locator->tunnel_key is "
                     "requried", __FUNCTION__);
            return NULL;
        }
    }
    else {
        if (vtep_phy_loc_row) {
            encap_type = vtep_phy_loc_row->encapsulation_type;
            dst_ip = vtep_phy_loc_row->dst_ip;
            if (vtep_phy_loc_row->tunnel_key)
                tunnel_key = *vtep_phy_loc_row->tunnel_key;
            else {
                VLOG_ERR("%s: Tunnel cannot be created/deleted/modified as "
                         "either logical_switch or locator->tunnel_key is "
                         "requried", __FUNCTION__);
                return NULL;
            }
        }
    }

    value_intf.type = "vxlan";
    memcpy(&value_intf.options, &options, sizeof(options));
    smap_add(&(value_intf.options), "remote_ip", dst_ip);
    snprintf(buf, 9, "%d", tunnel_key);
    smap_add(&(value_intf.options), "key", buf);

    OVSREC_INTERFACE_FOR_EACH_EQUAL(intf_row, &cursor_intf, &value_intf) {
        /* Can return zero, one or more records */
        VLOG_DBG("ovsdb interface found");
        return intf_row;
    }
}

static const struct ovsrec_logical_switch *
get_matching_logical_switch_from_ovsdb(const struct vteprec_logical_switch *vtep_ls_row)
{
    const struct ovsrec_logical_switch *ls_row;
    struct ovsrec_logical_switch value_ls;

    value_ls.name = vtep_ls_row->name;
    OVSREC_LOGICAL_SWITCH_FOR_EACH_EQUAL(ls_row, &cursor_ovs_ls, &value_ls) {
        /* Can return zero, one or more records */
        VLOG_DBG("ovsdb logical switch found");
        return ls_row;
    }
}


static void
ovsdb_reconfigure_()
{
    const struct vteprec_ucast_macs_local *vtep_mac_row = NULL;
    const struct ovsrec_mac *ovs_mac_row = NULL;

    ovsdb_idl_run(ovsdb_idl);

    VLOG_INFO("SM: before OVSREC_MAC_FOR_EACH_TRACKED");
    OVSREC_MAC_FOR_EACH_TRACKED(ovs_mac_row, ovsdb_idl)
    {
        VLOG_INFO("SM: ovs_row_idl_seqno = %d",
            ovsdb_idl_row_get_seqno(&ovs_mac_row->header_, OVSDB_IDL_CHANGE_INSERT));

        if (ovsdb_idl_row_get_seqno(&ovs_mac_row->header_,
            OVSDB_IDL_CHANGE_DELETE)>= ovsdb_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_DELETE for OVS MAC");
            vtep_mac_row = get_matching_mac_from_vtep(ovs_mac_row);
            delete_mac_config_from_vtep(vtep_mac_row, vtep_idl);

        } else if (ovsdb_idl_row_get_seqno(&ovs_mac_row->header_,
                   OVSDB_IDL_CHANGE_MODIFY)>= ovsdb_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_MODIFY for OVS MAC");
            vtep_mac_row = get_matching_mac_from_vtep(ovs_mac_row);
            update_mac_config_in_vtep(vtep_mac_row, ovs_mac_row, vtep_idl);

        } else if (ovsdb_idl_row_get_seqno(&ovs_mac_row->header_,
                   OVSDB_IDL_CHANGE_INSERT)>= ovsdb_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_INSERT for OVS MAC");
            insert_mac_config_in_vtep(ovs_mac_row, vtep_idl);
        }
    }
    VLOG_INFO("SM: after OVSREC_MAC_FOR_EACH_TRACKED");
}

static void
vtep_reconfigure_()
{
    const struct vteprec_ucast_macs_remote *vtep_mac_row = NULL;
    const struct vteprec_physical_port *vtep_physical_port_row = NULL;
    const struct vteprec_physical_locator *vtep_physical_locator_row = NULL;
    const struct vteprec_logical_switch *vtep_logical_switch_row = NULL;
    const struct ovsrec_mac *ovs_mac_row = NULL;
    const struct ovsrec_port *ovs_port_row = NULL;
    const struct ovsrec_bridge *ovs_br_row = NULL;
    const struct ovsrec_interface *ovs_interface_row = NULL;
    const struct ovsrec_logical_switch *ovs_logical_switch_row = NULL;
    static unsigned int tunnel_id = 0;

    ovsdb_idl_run(vtep_idl);

    VLOG_INFO("SM: before VTEPREC_UCAST_MACS_REMOTE_FOR_EACH_TRACKED");
    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH_TRACKED(vtep_mac_row, vtep_idl)
    {
        VLOG_INFO("SM: vtep_row_idl_seqno = %d",
                        ovsdb_idl_row_get_seqno(&vtep_mac_row->header_,
                        OVSDB_IDL_CHANGE_INSERT));
        if (ovsdb_idl_row_get_seqno(&vtep_mac_row->header_,
            OVSDB_IDL_CHANGE_DELETE)>= vtep_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_DELETE for VTEP MAC");
            ovs_mac_row = get_matching_mac_from_ovsdb(vtep_mac_row);
            ovs_br_row = get_matching_bridge_from_ovsdb();
            delete_mac_config_from_ovsdb(ovs_mac_row, ovsdb_idl);
            /* Delete tunnel */
            vtep_delete_tunnel(vtep_mac_row, ovs_br_row);

        } else if (ovsdb_idl_row_get_seqno(&vtep_mac_row->header_,
                   OVSDB_IDL_CHANGE_MODIFY)>= vtep_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_MODIFY for VTEP MAC");
            ovs_mac_row = get_matching_mac_from_ovsdb(vtep_mac_row);
            update_mac_config_in_ovsdb(ovs_mac_row, vtep_mac_row, ovsdb_idl);
            VLOG_ERR("%s: Modification of tunnel is not supported", __FUNCTION__);
        } else if (ovsdb_idl_row_get_seqno(&vtep_mac_row->header_,
                  OVSDB_IDL_CHANGE_INSERT)>= vtep_idl_seqno){
            VLOG_INFO("SM: OVSDB_IDL_CHANGE_INSERT for VTEP MAC");
            ovs_br_row = get_matching_bridge_from_ovsdb();
            /* Create tunnel */
            vtep_create_tunnel(vtep_mac_row,
                                ovs_br_row,
                                &tunnel_id);
           insert_mac_config_in_ovsdb(vtep_mac_row, ovsdb_idl);
        }
    }
    VLOG_INFO("SM: after VTEPREC_UCAST_MACS_REMOTE_FOR_EACH_TRACKED");

    VTEPREC_PHYSICAL_PORT_FOR_EACH_TRACKED(vtep_physical_port_row, vtep_idl)
    {
        if (ovsdb_idl_row_get_seqno(&vtep_physical_port_row->header_,
            OVSDB_IDL_CHANGE_DELETE)>= vtep_idl_seqno){
            ovs_port_row = get_matching_port_from_ovsdb(vtep_physical_port_row);
            delete_port_config_from_ovsdb(ovs_port_row, ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_physical_port_row->header_,
                   OVSDB_IDL_CHANGE_MODIFY)>= vtep_idl_seqno){
            ovs_port_row = get_matching_port_from_ovsdb(vtep_physical_port_row);
            update_port_config_in_ovsdb(ovs_port_row,
                                        vtep_physical_port_row, ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_physical_port_row->header_,
                   OVSDB_IDL_CHANGE_INSERT)>= vtep_idl_seqno){
            insert_port_config_in_ovsdb(vtep_physical_port_row, ovsdb_idl);
        }
    }

    VTEPREC_PHYSICAL_LOCATOR_FOR_EACH_TRACKED(vtep_physical_locator_row, vtep_idl)
    {
        if (ovsdb_idl_row_get_seqno(&vtep_physical_locator_row->header_,
            OVSDB_IDL_CHANGE_DELETE)>= vtep_idl_seqno){
            ovs_interface_row = get_matching_interface_from_ovsdb(NULL,
                                            vtep_physical_locator_row);
            delete_interface_config_from_ovsdb(ovs_interface_row, ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_physical_locator_row->header_,
                   OVSDB_IDL_CHANGE_MODIFY)>= vtep_idl_seqno){
            ovs_interface_row = get_matching_interface_from_ovsdb(NULL,
                                            vtep_physical_locator_row);
            update_interface_config_in_ovsdb(ovs_interface_row,
                                          vtep_physical_locator_row, ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_physical_locator_row->header_,
                                    OVSDB_IDL_CHANGE_INSERT)>= vtep_idl_seqno){
            insert_interface_config_in_ovsdb(vtep_physical_locator_row,
                                             ovsdb_idl);
        }
    }

    VTEPREC_LOGICAL_SWITCH_FOR_EACH_TRACKED(vtep_logical_switch_row, vtep_idl)
    {
        if (ovsdb_idl_row_get_seqno(&vtep_logical_switch_row->header_,
                                    OVSDB_IDL_CHANGE_DELETE)>= vtep_idl_seqno){
            ovs_logical_switch_row = get_matching_logical_switch_from_ovsdb(
                                        vtep_logical_switch_row);
            delete_logical_switch_config_from_ovsdb(ovs_logical_switch_row,
                                                    ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_logical_switch_row->header_,
                                     OVSDB_IDL_CHANGE_MODIFY)>= vtep_idl_seqno){
            ovs_logical_switch_row = get_matching_logical_switch_from_ovsdb(
                                            vtep_logical_switch_row);
            update_logical_switch_config_in_ovsdb(ovs_logical_switch_row,
                                            vtep_logical_switch_row, ovsdb_idl);

        } else if (ovsdb_idl_row_get_seqno(&vtep_logical_switch_row->header_,
                                    OVSDB_IDL_CHANGE_INSERT)>= vtep_idl_seqno){
            insert_logical_switch_config_in_ovsdb(vtep_logical_switch_row,
                                                  ovsdb_idl, NULL);
        }
    }
}

static int
ovsdb_reconfigure(void)
{
    int rc = 0;
    unsigned int new_ovsdb_idl_seqno = ovsdb_idl_get_seqno(ovsdb_idl);

    VLOG_INFO("SM: Inside ovsdb_reconfigure");
    VLOG_INFO("SM: ovsdb_idl_seqno = %d\n", ovsdb_idl_seqno);
    VLOG_INFO("SM: new_ovsdb_idl_seqno = %d\n", new_ovsdb_idl_seqno);
    if (new_ovsdb_idl_seqno == ovsdb_idl_seqno) {
        VLOG_INFO("SM: No change in ovsdb_reconfigure seqno");
        /* There was no change in the DB. */
        return rc;
    }

    ovsdb_reconfigure_();

    /* Update IDL sequence # after we've handled everything. */
    ovsdb_idl_seqno = new_ovsdb_idl_seqno;


    /* All changes processed - clear the change track */
    ovsdb_idl_track_clear(ovsdb_idl);

    return (rc + 1);

} /* ovsdb_reconfigure */

static int
vtep_reconfigure(void)
{
    int rc = 0;
    unsigned int new_vtep_idl_seqno = ovsdb_idl_get_seqno(vtep_idl);

    VLOG_INFO("SM: Inside vtep_reconfigure");
    VLOG_INFO("SM: vtep_idl_seqno = %d\n", vtep_idl_seqno);
    VLOG_INFO("SM: new_vtep_idl_seqno = %d\n", new_vtep_idl_seqno);
    if (new_vtep_idl_seqno == vtep_idl_seqno) {
        VLOG_INFO("SM: No change in vtep_reconfigure seqno");
        /* There was no change in the DB. */
        return rc;
    }

    vtep_reconfigure_();

    /* Update IDL sequence # after we've handled everything. */
    vtep_idl_seqno = new_vtep_idl_seqno;

    /* All changes processed - clear the change track */
    ovsdb_idl_track_clear(vtep_idl);

    return (rc + 1);

} /* vtep_reconfigure */

void
ovsdb_run(void)
{
    struct ovsdb_idl_txn *txn;

    VLOG_INFO("SM: Inside ovsdb_run");
    /* Process a batch of messages from HW-VTEP. */
    ovsdb_idl_run(ovsdb_idl);

    if (ovsdb_idl_is_lock_contended(ovsdb_idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "Another ovsdb process is running, "
                    "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(ovsdb_idl)) {
        return;
    }

    if (ovsdb_reconfigure()) {
        VLOG_INFO("SM: ovsdb_reconfigure is set");
        txn = ovsdb_idl_txn_create(ovsdb_idl);
        /* Some OVSDB write needs to happen. */
        ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
    }
    VLOG_INFO("SM: Exiting ovsdb_run");
    return;

} /* ovsdb_run */

void
vtep_run(void)
{
    struct ovsdb_idl_txn *txn;

    VLOG_INFO("SM: Inside vtep_run");
    /* Process a batch of messages from HW-VTEP. */
    ovsdb_idl_run(vtep_idl);

    if (ovsdb_idl_is_lock_contended(vtep_idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "Another vtep process is running, "
                    "disabling this process until it goes away");

        return;
    } else if (!ovsdb_idl_has_lock(vtep_idl)) {
        return;
    }

    if (vtep_reconfigure()) {
        txn = ovsdb_idl_txn_create(vtep_idl);
        /* Some OVSDB write needs to happen. */
        ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
    }

    VLOG_INFO("SM: Exiting vtep_run");
    return;
} /* vtep_run */

void
ovsdb_wait(void)
{
    ovsdb_idl_wait(ovsdb_idl);
    return;
} /* ovsdb_wait */

void
vtep_wait(void)
{
    ovsdb_idl_wait(vtep_idl);
    return;

} /* vtep_wait */

/* When exiting ovsdb destroy the idl cache. */
void
ovsdb_exit(void)
{
    ovsdb_idl_destroy(ovsdb_idl);
    return;
} /* ovsdb_exit */

/* When exiting vtep destroy the idl cache. */
void
vtep_exit(void)
{
    ovsdb_idl_destroy(vtep_idl);
    return;
} /* vtep_exit */
