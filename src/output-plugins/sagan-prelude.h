/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-prelude.h  */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBPRELUDE

int setup_analyzer(idmef_analyzer_t *);
int add_int_data(_SaganConfig *, idmef_alert_t *, const char *, uint32_t );
int event_to_impact(_SaganConfig *, int, idmef_alert_t *);
int event_to_reference(char *, idmef_classification_t *);
int event_to_source_target(_SaganConfig *, char *, char *, int ,int ,int , idmef_alert_t *);
int syslog_to_data( _SaganConfig *,  char * , char * , int , char *, idmef_alert_t * );
int add_byte_data( _SaganConfig *, idmef_alert_t *, const char *, const unsigned char *, size_t);
int add_sagan_reference(idmef_classification_t *, char *);

#endif

