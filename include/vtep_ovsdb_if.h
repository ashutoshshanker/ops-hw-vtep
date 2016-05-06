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

#ifndef _VTEP_OVSDB_IF_H
#define _VTEP_OVSDB_IF_H

#include "hash.h"
#include "shash.h"

extern void vtep_ovsdb_init(char *vtep_ovsdb_sock);
extern void ovsdb_run();
extern void vtep_run();
extern void ovsdb_wait();
extern void vtep_wait();
extern void ovsdb_exit();
extern void vtep_exit();

#endif /* _VTEP_OVSDB_IF_H */
