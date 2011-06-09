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

/* sagan-snort.h  */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

int  db_connect( void );
char *db_query ( int,  char * );
int  get_sensor_id ( char *,  char *,  char *,  int , int  );
uint64_t get_cid ( int , int );

void record_last_cid ( void );

int  get_sig_sid( char *,  char *,
                  char *,  char *,
                  int         ,  int  );

void insert_event (int, uint64_t, int, int, char *, char * );

void insert_hdr (int , uint64_t,
                 char *,  char *,
                 int, int, int, int, int);

void insert_payload ( int,  uint64_t, char *,  int );

void query_reference ( char *, char *, int, int );

struct db_thread_args {
        char *ip_src;
        char *ip_dst;
        int  found;
        int  pri;
        char *message;
        uint64_t cid;
        int endian;
        int dst_port;
        int src_port;
        char *date;
        char *time;
        };

#endif
