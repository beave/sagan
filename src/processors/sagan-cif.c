/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* sagan-cif.c
*
* This process is to lookup data via the CIF (Collective Intelligence Framework).
* For more information about CIF,  please see:
*
* https://code.google.com/p/collective-intelligence-framework/
* http://csirtgadgets.org/
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#if defined(HAVE_LIBJSON) || defined(HAVE_LIBJSON_C)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json/json.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "sagan-gen-msg.h"
#include "sagan-cif.h"

#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _Sagan_Processor_Generator *generator;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _Sagan_CIF_Ignore_List *SaganWebsenseIgnoreList;
struct _Sagan_CIF_Queue *SaganWebsenseQueue;
struct _Sagan_CIF_Cache *SaganWebsenseCache;

struct _Sagan_Processor_Info *processor_info_cif;

pthread_mutex_t SaganProcCIFWorkMutex=PTHREAD_MUTEX_INITIALIZER;

sbool cif_cache_clean_lock=0;
int cif_queue=0;





#endif
