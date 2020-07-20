/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBYAML

/************************/
/* Minimum YAML version */
/************************/

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/*****************/
/* Primary types */
/*****************/

#define		YAML_TYPE_VAR		1
#define		YAML_TYPE_SAGAN_CORE	2
#define		YAML_TYPE_PROCESSORS	3
#define		YAML_TYPE_OUTPUT	4
#define		YAML_TYPE_RULES		5
#define		YAML_TYPE_INCLUDES	6

/*******************/
/* Secondary types */
/*******************/

/* Sagan core */

#define 	YAML_SAGAN_CORE_CORE			101
#define		YAML_SAGAN_CORE_MMAP_IPC		102
#define		YAML_SAGAN_CORE_IGNORE_LIST		103
#define		YAML_SAGAN_CORE_GEOIP			104
#define 	YAML_SAGAN_CORE_LIBLOGNORM		105
#define		YAML_SAGAN_CORE_PLOG			106
#define		YAML_SAGAN_CORE_REDIS			107
#define		YAML_SAGAN_CORE_PARSE_IP		108
#define		YAML_SAGAN_CORE_RULESET_TRACKING	109


/* Processors */

#define		YAML_PROCESSORS_TRACK_CLIENTS	200
#define		YAML_PROCESSORS_PERFMON		201
#define		YAML_PROCESSORS_BLACKLIST	202
#define		YAML_PROCESSORS_BLUEDOT		203
#define		YAML_PROCESSORS_BROINTEL	204
#define		YAML_PROCESSORS_DYNAMIC_LOAD	205
#define		YAML_PROCESSORS_CLIENT_STATS	206
#define		YAML_PROCESSORS_STATS_JSON	207

/* Outputs */

#define		YAML_OUTPUT_UNIFIED2		300
#define		YAML_OUTPUT_EXTERNAL		301
#define		YAML_OUTPUT_SMTP		302
#define		YAML_OUTPUT_SNORTSAM		303
#define		YAML_OUTPUT_SYSLOG		304
#define		YAML_OUTPUT_FAST		305
#define		YAML_OUTPUT_ALERT		306
#define		YAML_OUTPUT_EVE			307

void Load_YAML_Config( char * );

#endif
