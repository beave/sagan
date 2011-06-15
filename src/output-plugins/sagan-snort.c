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

/* sagan-db.c 
 *
 * Threaded function for database support.   These functions are for both
 * MySQL and PostgreSQL.   These allow Sagan to report to Snort databases
 * where we'll attempt to correlate the events. 
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-snort.h"


#include "version.h"


#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
MYSQL    *connection, *mysql;
#endif

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
PGconn   *psql;
PGresult *result;
char pgconnect[2048];
#endif

//struct _SaganConfig *config;
struct _SaganCounters *counters;

struct rule_struct *rulestruct;

pthread_mutex_t db_mutex;


/********************************************/
/* Connection to various types of databases */
/********************************************/

int db_connect( _SaganConfig *config ) { 

char *dbh=NULL;
char *dbu=NULL;
char *dbp=NULL;
char *dbn=NULL;

dbu = config->dbuser;
dbh = config->dbhost;
dbp = config->dbpassword;
dbn = config->dbname;

/********************/
/* MySQL connection */
/********************/

#ifdef HAVE_LIBMYSQLCLIENT_R
if ( config->dbtype == 1 ) { 

mysql_thread_init();
mysql = mysql_init(NULL);

if ( mysql == NULL ) { 
   removelockfile(config);
   sagan_log(config, 1, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__);
   }


my_bool reconnect = 1;
mysql_options(mysql,MYSQL_READ_DEFAULT_GROUP,config->dbname);

/* Re-connect to the database if the connection is lost */

mysql_options(mysql,MYSQL_OPT_RECONNECT, &reconnect);

if (!mysql_real_connect(mysql, dbh, dbu, dbp, dbn, MYSQL_PORT, NULL, 0)) {
     sagan_log(config, 1, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__, mysql_errno(mysql), mysql_error(mysql));
     }

}
#endif

/*************************/
/* PostgreSQL connection */
/*************************/

#ifdef HAVE_LIBPQ
if ( config->dbtype == 2 ) { 

//isthreadsafe = PQisthreadsafe(); 	// check

snprintf(pgconnect, sizeof(pgconnect), "hostaddr = '%s' port = '%d' dbname = '%s' user = '%s' password = '%s' connect_timeout = '30'", dbh, 5432 , dbn, dbu, dbp); 

psql = PQconnectdb(pgconnect);

if (!psql) { 
   removelockfile(config);
   sagan_log(config, 1, "[%s, line %d] PostgreSQL: PQconnect Error", __FILE__,  __LINE__);
   }

if (PQstatus(psql) != CONNECTION_OK) { 
   removelockfile(config);
   sagan_log(config, 1, "[%s, line %d] PostgreSQL status not OK", __FILE__,  __LINE__);
   }

} 
#endif

return(0);
}  /* End of db_connect */

/****************************************************************************
 * Query Database | iorq == 0 (SELECT) iorq == 1 (INSERT)                   *
 * For SELECT,  we typically only want one value back (row[0]) so return it *
 * For INSERT,  we don't need or get any results back                       *
 ****************************************************************************/

char *db_query ( _SaganDebug *debug, _SaganConfig *config, char *sql ) { 

char sqltmp[MAXSQL]; 	/* Make this a MAXSQL or something */
char *re=NULL;		/* "return" point for row */

int mysql_last_errno = 0; 
int mysql_reconnect_count = 0;

pthread_mutex_lock( &db_mutex );

strlcpy(sqltmp, sql, sizeof(sqltmp));


if ( debug->debugsql ) sagan_log(config, 0, "%s", sqltmp); 

#ifdef HAVE_LIBMYSQLCLIENT_R
if ( config->dbtype == 1 ) {

MYSQL_RES *res;
MYSQL_ROW row;

while ( mysql_real_query(mysql, sqltmp,  strlen(sqltmp)) != 0 ) { 

    mysql_last_errno = mysql_errno(mysql);
    
    if ( mysql_last_errno == CR_CONNECTION_ERROR || 
         mysql_last_errno == CR_CONN_HOST_ERROR || 
	 mysql_last_errno == CR_SERVER_GONE_ERROR ) { 
	 mysql_reconnect_count++;
	 sagan_log(config, 0, "[%s, line %d] Lost connection to MySQL database. Trying %d", __FILE__,  __LINE__, mysql_reconnect_count);
	 sleep(2);		// Give the DB time to recover

	 } else { 

	removelockfile(config);
        sagan_log(config, 1, "[%s, line %d] MySQL Error [%u:] \"%s\"\nOffending SQL statement: %s\n", __FILE__,  __LINE__, mysql_errno(mysql), mysql_error(mysql), sqltmp);
	}
   
   }


if ( mysql_reconnect_count != 0 ) { 			/* If there's a reconnect_count,  we must of lost connection */
   sagan_log(config, 0, "MySQL connection re-established!"); 	/* Log it */
   mysql_reconnect_count=0;				/* Reset the counter */
   }

res = mysql_use_result(mysql);

if ( res != NULL ) { 
   while((row = mysql_fetch_row(res))) {
   snprintf(sqltmp, sizeof(sqltmp), "%s", row[0]);
   re=sqltmp;
   }
 }

mysql_free_result(res);
pthread_mutex_unlock( &db_mutex );
return(re);
}
#else
if ( config->dbtype == 1 ) {
    removelockfile(config);
    sagan_log(config, 1, "Sagan was not compiled with MySQL support.  Aborting!");
}
#endif

#ifdef HAVE_LIBPQ
if ( config->dbtype == 2 ) {

if (( result = PQexec(psql, sqltmp )) == NULL ) { 
   //removelockfile();
   sagan_log(config, 0, "[%s, line %d] PostgreSQL Error: %s", __FILE__,  __LINE__, PQerrorMessage( psql ));
   }

if (PQresultStatus(result) != PGRES_COMMAND_OK && 
    PQresultStatus(result) != PGRES_TUPLES_OK) {
   sagan_log(config, 0, "[%s, line %d] PostgreSQL Error: %s", __FILE__,  __LINE__, PQerrorMessage( psql ));
   PQclear(result);
   //removelockfile();
   sagan_log(0, "DB Query failed: %s", sqltmp);
   }

if ( PQntuples(result) != 0 ) { 
    re = PQgetvalue(result,0,0);
    }

PQclear(result);
pthread_mutex_unlock( &db_mutex);
return(re);

}
#else
if ( config->dbtype == 2 ) {
    removelockfile(config);
    sagan_log(config, 1, "[%s, line %d] Sagan was not compiled with PostgreSQL support.  Aborting!", __FILE__, __LINE__);
}
#endif

return(0);
}

/*****************************************************************************/
/* Get's the current sensor ID or creates a new one if this is the first run */
/*****************************************************************************/

//int get_sensor_id ( _SaganDebug *debug, char *hostname,  char *interface,  char *filter,  int detail, int dbtype ) { 
int get_sensor_id ( _SaganDebug *debug,  _SaganConfig *config ) { 


char sqltmp[MAXSQL]; 
char *sql;
char *sqlout;

snprintf(sqltmp, sizeof(sqltmp), "SELECT sid FROM sensor WHERE hostname='%s' AND interface='%s' AND filter='%s' AND detail='%d' AND encoding='0'",  config->sagan_hostname, config->sagan_interface, config->sagan_filter, config->sagan_detail);
sql=sqltmp;
sqlout = db_query(debug,  config, sql);

if ( sqlout == NULL ) { 

   /* Insert new sensor ID */
   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) VALUES ('%s', '%s', '%s', '%u', '0', '0')", config->sagan_hostname, config->sagan_interface, config->sagan_filter, config->sagan_detail);
   sql=sqltmp; 
   db_query(debug, config, sql);

   /* Get new sensor ID */
   snprintf(sqltmp, sizeof(sqltmp), "SELECT sid FROM sensor WHERE hostname='%s' AND interface='%s' AND filter='%s' AND detail='%d' AND encoding='0'", config->sagan_hostname, config->sagan_interface, config->sagan_filter, config->sagan_detail);
   sql=sqltmp;
   sqlout = db_query(debug, config, sql);
   }

config->sensor_id = atoi(sqlout);
return(0);

}

/******************************************/
/* Get the last used CID and increment it */
/******************************************/

uint64_t get_cid ( _SaganDebug *debug, _SaganConfig *config ) { 

char sqltmp[MAXSQL]; 
char *sql;
char *sqlout;
uint64_t t_cid; 


snprintf(sqltmp, sizeof(sqltmp), "SELECT last_cid from sensor where sid=%d and hostname='%s' and interface='%s' and filter='%s' and detail=%d", config->sensor_id, config->sagan_hostname, config->sagan_interface, config->sagan_filter, config->sagan_detail);

sql=sqltmp; 
sqlout = db_query( debug, config, sql );

if ( sqlout == NULL ) { 
   t_cid = 0; 		/* Returned NULL,  no CID found */
   } else { 
   t_cid = atol(sqlout);
   }

return(t_cid);
}


/*********************************************************/
/* Get signature ID.  If on doesn't exsist,  put one in. */
/*********************************************************/

int get_sig_sid ( SaganEvent *Event ) {


char sqltmp[MAXSQL];
char *sql;
char *sqlout;
int sig_class_id;
int  t_sig_id; 

snprintf(sqltmp, sizeof(sqltmp), "SELECT sig_class_id from sig_class where sig_class_name='%s'", rulestruct[Event->found].s_classtype);
sql=sqltmp;
sqlout = db_query( Event->debug, Event->config, sql ); 

if ( sqlout == NULL ) {
   
   /* classification hasn't been recorded in sig_class,  so put it in */

   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO sig_class(sig_class_id, sig_class_name) VALUES (DEFAULT, '%s')", rulestruct[Event->found].s_classtype);
   sql=sqltmp;
   db_query( Event->debug, Event->config, sql);

   /* Grab new ID */

   snprintf(sqltmp, sizeof(sqltmp), "SELECT sig_class_id from sig_class where sig_class_name='%s'", rulestruct[Event->found].s_classtype);
   sql=sqltmp;
   sqlout = db_query( Event->debug, Event->config, sql );
   }
 
sig_class_id = atoi(sqlout);

/* Look for the signature id */

snprintf(sqltmp, sizeof(sqltmp), "SELECT sig_id FROM signature WHERE sig_name='%s' AND sig_rev=%s AND sig_sid=%s", rulestruct[Event->found].s_msg, rulestruct[Event->found].s_rev, rulestruct[Event->found].s_sid);
sql=sqltmp;


sqlout = db_query( Event->debug, Event->config, sql );

/* If not found, create a new entry for it */

if ( sqlout == NULL ) {

   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO signature(sig_name, sig_class_id, sig_priority, sig_rev, sig_sid) VALUES ('%s', '%d', '%d', '%s', '%s' )", rulestruct[Event->found].s_msg, sig_class_id, rulestruct[Event->found].s_pri, rulestruct[Event->found].s_rev, rulestruct[Event->found].s_sid );
   sql=sqltmp;
   db_query( Event->debug, Event->config, sql );

   /* Get the new ID of the new entry */
   snprintf(sqltmp, sizeof(sqltmp), "SELECT sig_id FROM signature WHERE sig_name='%s' AND sig_rev=%s AND sig_sid=%s", rulestruct[Event->found].s_msg, rulestruct[Event->found].s_rev, rulestruct[Event->found].s_sid );
   sql=sqltmp;
   sqlout = db_query( Event->debug, Event->config, sql );
   }

t_sig_id = atoi(sqlout);
return(t_sig_id);

}


/***************************/
/* Insert into event table */
/***************************/

void insert_event ( SaganEvent *Event, int sig_sid, char *date,  char *time ) { 

char sqltmp[MAXSQL];
char *sql;

pthread_mutex_lock( &db_mutex );

snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO event(sid, cid, signature, timestamp) VALUES ('%d', '%" PRIu64 "', '%d', '%s %s')", Event->config->sensor_id, Event->cid, sig_sid, date, time );
sql=sqltmp;

pthread_mutex_unlock( &db_mutex );

db_query( Event->debug, Event->config, sql );

}


/****************************************************************************************/
/* Insert data into iphdr and tcphdr - most of this is bogus as we're not really TCP/IP */
/****************************************************************************************/

void insert_hdr ( SaganEvent *Event,  char *ipsrc, char *ipdst )  {

char sqltmp[MAXSQL];
char *sql;

int ipproto = rulestruct[Event->found].ip_proto; 

/* Temp. store 32bit IP address for DB insertion */

/* 4 == IPv4 */

snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO iphdr VALUES ( '%d', '%" PRIu64 "', '%u', '%u', '4', '0', '0', '0', '0', '0', '0', '0', '%d', '0' )", Event->config->sensor_id, Event->cid, ip2bit(Event->config, ipsrc ), ip2bit(Event->config, ipdst), ipproto );

sql=sqltmp;
db_query( Event->debug, Event->config, sql );

/* "tcp" */
if ( ipproto == 6 )  {
snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO tcphdr VALUES ( '%d', '%" PRIu64 "', '%d', '%d', '0', '0', '0', '0', '0', '0', '0', '0'  )", Event->config->sensor_id, Event->cid, Event->src_port, Event->dst_port  );
sql=sqltmp;
db_query( Event->debug, Event->config, sql );
} 

/* "udp" */

if ( ipproto == 17 )  {
snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO udphdr VALUES ( '%d', '%" PRIu64 "', '%d', '%d', '0', '0' )", Event->config->sensor_id, Event->cid, Event->src_port, Event->dst_port  );
sql=sqltmp;
db_query( Event->debug, Event->config, sql );
}

/* Basic ICMP - Set to type 8 (echo) , code of  8 */
/* May expand on this if there's actually a use for it */

if ( ipproto == 1 ) { 
snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO icmphdr VALUES ( '%d', '%" PRIu64 "', '8', '8', '0', '0', '0' )", Event->config->sensor_id, Event->cid );
sql=sqltmp;
db_query( Event->debug, Event->config, sql );
}


}

/*****************************/
/* Insert into payload table */
/*****************************/

void insert_payload ( SaganEvent *Event,  char *t_hex_data ) { 

char sqltmp[MAXSQL]; 
char *sql;

pthread_mutex_lock( &db_mutex );
snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO data(sid, cid, data_payload) VALUES ('%d', '%" PRIu64 "', '%s')", Event->config->sensor_id, Event->cid, t_hex_data);
sql=sqltmp;
pthread_mutex_unlock( &db_mutex );
db_query( Event->debug, Event->config, sql );

}

/*******************/
/* Record last cid */
/*******************/

void record_last_cid ( _SaganDebug *debug, _SaganConfig *config )  { 

char sqltmp[MAXSQL];
char *sql;

snprintf(sqltmp, sizeof(sqltmp), "UPDATE sensor SET last_cid='%" PRIu64 "' where sid=%d and hostname='%s' and interface='%s' and filter='%s' and detail=%d", counters->sigcid, config->sensor_id, config->sagan_hostname, config->sagan_interface, config->sagan_filter, config->sagan_detail);
sql=sqltmp;
db_query( debug, config, sql );

}

/********************/
/* Reference system */
/********************/

void query_reference ( _SaganDebug *debug, _SaganConfig *config, char *ref, char *rule_sid, int sig_sid, int seq ) 
{

char *saveptr=NULL;
char *tmptoken1=NULL;
char *tmptoken2=NULL;
char reference[128];

int ref_system_id;
int ref_id;

char sqltmp[MAXSQL];
char *sql;
char *sqlout;


strlcpy(reference, ref, sizeof(reference));

tmptoken1 = strtok_r(reference, ",", &saveptr);
tmptoken2 = strtok_r(NULL, "," , &saveptr);

/* Look for improperly formated references */

if (tmptoken1 == NULL || tmptoken2 == NULL ) 
   { 
   sagan_log(config, 0, "Warning: \"reference:\" contains a NULL value.  Check sid: %s", rule_sid);
   return;
   }

snprintf(sqltmp, sizeof(sqltmp), "SELECT ref_system_id from reference_system where ref_system_name='%s'", tmptoken1);
sql=sqltmp;
sqlout = db_query( debug, config, sql );

/* reference_system hasn't been entered into the DB.  Do so now */

if ( sqlout == NULL )  { 
   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO reference_system (ref_system_id, ref_system_name) VALUES (DEFAULT, '%s')", tmptoken1);
   sql=sqltmp;
   db_query( debug, config, sql );

   snprintf(sqltmp, sizeof(sqltmp), "SELECT ref_system_id from reference_system where ref_system_name='%s'", tmptoken1);
   sql=sqltmp;
   sqlout = db_query( debug, config, sql );
   }

ref_system_id = atoi(sqlout);

snprintf(sqltmp, sizeof(sqltmp), "SELECT ref_id from reference where ref_system_id='%d' and ref_tag='%s'", ref_system_id, tmptoken2);
sql=sqltmp;
sqlout = db_query( debug, config, sql );

if ( sqlout == NULL )  { 
   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO reference (ref_id, ref_system_id, ref_tag) VALUES (DEFAULT, '%d', '%s')", ref_system_id, tmptoken2);
   sql=sqltmp;
   sqlout = db_query( debug, config, sql );

   snprintf(sqltmp, sizeof(sqltmp), "SELECT ref_id from reference where ref_system_id='%d' and ref_tag='%s'", ref_system_id, tmptoken2);
   sql=sqltmp;
   sqlout = db_query( debug, config, sql );

   }

ref_id = atoi(sqlout);

snprintf(sqltmp, sizeof(sqltmp), "SELECT sig_id from sig_reference where sig_id='%d' and ref_id='%d'", sig_sid,  ref_id); 
sql=sqltmp;
sqlout = db_query( debug, config, sql );

if ( sqlout == NULL )  { 
   snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO sig_reference (sig_id, ref_seq, ref_id) VALUES ('%d', '%d', '%d')", sig_sid, seq, ref_id);
   sql=sqltmp;
   sqlout = db_query( debug, config, sql );

   }

}


/***************************************************************************/
/* Snort specific thread code                                              */
/***************************************************************************/

void sagan_db_thread( SaganEvent *Event ) {

int sig_sid;
int i;
char *hex_data = NULL;
char message[MAX_SYSLOGMSG];

char ip_srctmp[65];
char ip_dsttmp[65];

char time[30];
char date[30];

snprintf(message, sizeof(message), "%s", Event->message); 
snprintf(ip_srctmp, sizeof(ip_srctmp), "%s", Event->ip_src);
snprintf(ip_dsttmp, sizeof(ip_dsttmp), "%s", Event->ip_dst);
snprintf(time, sizeof(time), "%s", Event->time);
snprintf(date, sizeof(date), "%s", Event->date);

sig_sid = get_sig_sid(Event);

insert_event( Event, sig_sid, date, time);
insert_hdr ( Event,  ip_srctmp, ip_dsttmp );

hex_data = fasthex(message, strlen(message));
insert_payload( Event, hex_data ); 

for (i = 0; i < rulestruct[Event->found].ref_count; i++ ) {
   query_reference( Event->debug, Event->config, rulestruct[Event->found].s_reference[i], rulestruct[Event->found].s_sid, sig_sid, i );
   }

pthread_mutex_lock( &db_mutex );
counters->threaddbc--;
pthread_mutex_unlock( &db_mutex );

pthread_exit(NULL);
}

#endif
