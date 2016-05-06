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
#include <config.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <dirs.h>
#include "util.h"
#include "command-line.h"
#include "fatal-signal.h"

#include "unixctl.h"
#include "daemon.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vswitch-idl.h"
#include "vtep_ovsdb_if.h"
#include "ovsdb-idl.h"
#include "vtep-idl.h"

VLOG_DEFINE_THIS_MODULE (vtep_main);

/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", program_name);
  else
    fprintf (stderr, "Usage : %s [OPTION...]\n\n" \
        "Vtep deamon. \n\n" \
        "-b, --boot               Execute boot startup configuration\n" \
        "-c, --command            Execute argument as command\n" \
        "-d, --daemon             Connect only to the specified daemon\n" \
        "-E, --echo               Echo prompt and command in -c mode\n" \
        "-C, --dryrun             Check configuration for validity and exit\n" \
        "-h, --help               Display this help and exit\n\n" \
        "Note that multiple commands may be executed from the command\n" \
        "line by passing multiple -c args, or by embedding linefeed\n" \
        "characters in one or more of the commands.\n\n", program_name);

  exit (status);
}

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(0);

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        VLOG_INFO_ONCE("nitish case 0");
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        VLOG_INFO_ONCE("nitish case 1");
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }

} /* parse_options */


/**
 * hw-vtep daemon's ovs-appctl callback function for exit command.
 *
 * @param conn is pointer appctl connection data struct.
 * @param argc OVS_UNUSED
 * @param argv OVS_UNUSED
 * @param exiting_ is pointer to a flag that reports exit status.
 */
static void
ops_hw_vtep_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
} /* ops_hw_vtep_exit */


/**
 * Main function for hw-vtep daemon.
 *
 * @param argc is the number of command line arguments.
 * @param argv is an array of command line arguments.
 *
 * @return  for success or exit status on daemon exit.
 */
int
main(int argc, char *argv[])
{
    char *appctl_path = NULL;
    struct unixctl_server *appctl;
    char *vtep_ovsdb_sock;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    fatal_ignore_sigpipe();

    /* Parse command line args and get the name of the OVSDB socket. */
    vtep_ovsdb_sock = parse_options(argc, argv, &appctl_path);

    /* Initialize the metadata for the IDL cache. */
    ovsrec_init();
    vteprec_init();

    /* Fork and return in child process; but don't notify parent of
     * startup completion yet. */
    daemonize_start();

    /* Create UDS connection for ovs-appctl. */
    retval = unixctl_server_create(appctl_path, &appctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    /* Register the ovs-appctl "exit" command for this daemon. */
    unixctl_command_register("exit", "", 0, 0, ops_hw_vtep_exit, &exiting);


    /* Notify parent of startup completion. */
    daemonize_complete();

    VLOG_INFO_ONCE("%s (OpenSwitch HW-Vtep Daemon) started", program_name);

    vtep_ovsdb_init(vtep_ovsdb_sock);
    free(vtep_ovsdb_sock);

    exiting = false;
    while (!exiting) {
        VLOG_INFO_ONCE("nitish calling vtep run");
        vtep_run();
        VLOG_INFO_ONCE("nitish calling ovsdb run");
        ovsdb_run();
        VLOG_INFO_ONCE("nitish called ovsdb run");
//        ovsdb_idl_loop_commit_and_wait(&vtep_idl_loop);
//        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
        unixctl_server_run(appctl);
        vtep_wait();
        ovsdb_wait();
        unixctl_server_wait(appctl);
    }


    vtep_exit();
    ovsdb_exit();
    unixctl_server_destroy(appctl);

    return 0;
}
