/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

#define 	YAML_SAGAN_CORE_CORE		1
#define		YAML_SAGAN_CORE_MMAP_IPC	2
#define		YAML_SAGAN_CORE_IGNORE_LIST	3
#define		YAML_SAGAN_CORE_GEOIP		4
#define 	YAML_SAGAN_CORE_LIBLOGNORM	5
#define		YAML_SAGAN_CORE_PLOG		6
#define		YAML_SAGAN_CORE_REDIS		7

/* Processors */

#define		YAML_PROCESSORS_TRACK_CLIENTS	7
#define		YAML_PROCESSORS_PERFMON		8
#define		YAML_PROCESSORS_BLACKLIST	9
#define		YAML_PROCESSORS_BLUEDOT		10
#define		YAML_PROCESSORS_BROINTEL	11
#define		YAML_PROCESSORS_DYNAMIC_LOAD	12

/* Outputs */

#define		YAML_OUTPUT_UNIFIED2		13
#define		YAML_OUTPUT_EXTERNAL		14
#define		YAML_OUTPUT_SMTP		15
#define		YAML_OUTPUT_SNORTSAM		16
#define		YAML_OUTPUT_SYSLOG		17
#define		YAML_OUTPUT_FAST		18
#define		YAML_OUTPUT_ALERT		19
#define		YAML_OUTPUT_EVE			20

void Load_YAML_Config( char * );

#endif
