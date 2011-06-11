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

/* sagan-logzilla.c
 *
 * Logs to a Logzilla SQL database.  
 * See http://code.google.com/p/php-syslog-ng/
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "sagan.h"

#include "sagan-logzilla.h"
#include "version.h"


#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
MYSQL    *connection, *mysql_logzilla;
#endif

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
PGconn   *psql_logzilla;
PGresult *result;
char pgconnect[2048];
#endif

struct _SaganConfig *config;
struct _SaganCounters *counters;

pthread_mutex_t logzilla_db_mutex;

int logzilla_db_connect( void ) {

char *dbh=NULL;
char *dbu=NULL;
char *dbp=NULL;
char *dbn=NULL;

dbu = config->logzilla_user;
dbh = config->logzilla_dbhost;
dbp = config->logzilla_password;
dbn = config->logzilla_dbname;

/********************/
/* MySQL connection */
/********************/

#ifdef HAVE_LIBMYSQLCLIENT_R
if ( config->logzilla_dbtype == 1 ) {

mysql_thread_init();
mysql_logzilla = mysql_init(NULL);

if ( mysql_logzilla == NULL ) {
   removelockfile();
   sagan_log(1, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__ );
   }


my_bool reconnect = 1;
mysql_options(mysql_logzilla,MYSQL_READ_DEFAULT_GROUP,config->logzilla_dbname);

/* Re-connect to the database if the connection is lost */

mysql_options(mysql_logzilla,MYSQL_OPT_RECONNECT, &reconnect);

if (!mysql_real_connect(mysql_logzilla, dbh, dbu, dbp, dbn, MYSQL_PORT, NULL, 0)) {
     sagan_log(1, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__, mysql_errno(mysql_logzilla), mysql_error(mysql_logzilla));
     }

}
#endif
/*************************/
/* PostgreSQL connection */
/*************************/

#ifdef HAVE_LIBPQ
if ( config->logzilla_dbtype == 2 ) {

//isthreadsafe = PQisthreadsafe();      // check

snprintf(pgconnect, sizeof(pgconnect), "hostaddr = '%s' port = '%d' dbname = '%s' user = '%s' password = '%s' connect_timeout = '30'", dbh, 5432 , dbn, dbu, dbp);

psql_logzilla = PQconnectdb(pgconnect);

if (!psql_logzilla) {
   removelockfile();
   sagan_log(1, "[%s, line %d] PostgreSQL: PQconnect Error", __FILE__, __LINE__);
   }

if (PQstatus(psql_logzilla) != CONNECTION_OK) {
   removelockfile();
   sagan_log(1, "[%s, line %d] PostgreSQL status not OK", __FILE__, __LINE__);
   }

}
#endif

return(0);
}  /* End of logzilla_connect */


/****************************************************************************
 * Query Database | iorq == 0 (SELECT) iorq == 1 (INSERT)                   *
 * For SELECT,  we typically only want one value back (row[0]) so return it *
 * For INSERT,  we don't need or get any results back                       *
 ****************************************************************************/

char *logzilla_db_query ( int dbtype,  char *sql ) {

pthread_mutex_lock( &logzilla_db_mutex );

char sqltmp[MAXSQL];    /* Make this a MAXSQL or something */
char *re=NULL;          /* "return" point for row */

int mysql_last_errno = 0;
int mysql_reconnect_count = 0;

strlcpy(sqltmp, sql, sizeof(sqltmp));

#ifdef HAVE_LIBMYSQLCLIENT_R
if ( config->logzilla_dbtype == 1 ) {

MYSQL_RES *logzilla_res;
MYSQL_ROW logzilla_row;

while ( mysql_real_query(mysql_logzilla, sqltmp,  strlen(sqltmp)) != 0 ) { 
   
   mysql_last_errno = mysql_errno(mysql_logzilla);

   if ( mysql_last_errno == CR_CONNECTION_ERROR ||
        mysql_last_errno == CR_CONN_HOST_ERROR ||
	mysql_last_errno == CR_SERVER_GONE_ERROR ) {
	mysql_reconnect_count++;
	sagan_log(0, "[%s, line %d] Lost connection to MySQL database. Trying %d",  __FILE__, __LINE__, mysql_reconnect_count);
	sleep(2);              // Give the DB time to recover

	} else { 
	
   sagan_log(1, "[%s, line %d] MySQL Error [%u:] \"%s\"\nOffending SQL statement: %s", __FILE__, __LINE__, mysql_errno(mysql_logzilla), mysql_error(mysql_logzilla), sqltmp);
   }

}

if ( mysql_reconnect_count != 0 ) {                     /* If there's a reconnect_count,  we must of lost connection */
   sagan_log(0, "MySQL connection re-established!");    /* Log it */
   mysql_reconnect_count=0;                             /* Reset the counter */
   }


logzilla_res = mysql_use_result(mysql_logzilla);

if ( logzilla_res != NULL ) {
   while((logzilla_row = mysql_fetch_row(logzilla_res))) {
   snprintf(sqltmp, sizeof(sqltmp), "%s", logzilla_row[0]);
   re=sqltmp;
   }
 }

mysql_free_result(logzilla_res);
pthread_mutex_unlock( &logzilla_db_mutex );
return(re);
}
#else
removelockfile();
sagan_log(1, "Sagan was not compiled with MySQL support.  Aborting!");
#endif

#ifdef HAVE_LIBPQ
if ( config->logzilla_dbtype == 2 ) {

if (( result = PQexec(psql_logzilla, sql )) == NULL ) {
//   removelockfile();
   sagan_log(0, "[%s, line %d] PostgreSQL Error: %s", __FILE__, __LINE__, PQerrorMessage( psql_logzilla ));
   }

if ( PQntuples(result) != 0 ) {
    re = PQgetvalue(result,0,0);
    }

PQclear(result);
pthread_mutex_unlock( &logzilla_db_mutex);
return(re);

}
#else
removelockfile();
sagan_log(1, "[%s, line %d] Sagan was not compiled with PostgreSQL support.  Aborting!", __FILE__, __LINE__);
#endif

return(0);
}


void sagan_logzilla_thread ( SaganEvent *Event ) { 

char sqltmp[MAXSQL];
char *sql=NULL;

char escprg[MAXPROGRAM];
char escmsg[MAX_SYSLOGMSG];

snprintf(escprg, sizeof(escprg), "%s", sql_escape(Event->program, 1));
snprintf(escmsg, sizeof(escmsg), "%s", sql_escape(Event->message, 1));

snprintf(sqltmp, sizeof(sqltmp), "INSERT INTO logs (host, facility, priority, level, tag, program, msg, fo, lo) VALUES ('%s', '%s', '%s', '%s', '%s', %s, %s, '%s %s', '%s %s')", Event->host, Event->facility, Event->priority, Event->level, Event->tag, escprg , escmsg, Event->date, Event->time, Event->date, Event->time  );


sql=sqltmp;
logzilla_db_query(config->logzilla_dbtype, sql);

pthread_mutex_lock ( &logzilla_db_mutex );
counters->threadlogzillac--;
pthread_mutex_unlock ( &logzilla_db_mutex );

}

#endif
