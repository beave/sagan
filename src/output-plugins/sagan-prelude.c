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

/* sagan-prelude.c 
 *
 * Threaded output for the Prelude framework.  For more information about
 * Prelude,  please see: http://www.prelude-technologies.com
 * 
 * Some of this code is based off Snort's Prelude output plug in 
 * (spo_alert_prelude.c). 
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBPRELUDE

#include <stdio.h>
#include <string.h>
#include <libprelude/prelude.h>
#include <pthread.h>
#include <inttypes.h>
#include "version.h"

#include "sagan.h"

#include "sagan-prelude.h"

struct _SaganCounters *counters;

#define ANALYZER_CLASS "Log Analyzer"
#define ANALYZER_MODEL "Sagan"
#define ANALYZER_MANUFACTURER "http://sagan.quadrantsec.com"
#define ANALYZER_SID_URL "https://wiki.quadrantsec.com/bin/view/Main/"
#define DEFAULT_ANALYZER_NAME "sagan"
#define ANALYZER_INTERFACE "syslog"

prelude_client_t *preludeclient;

struct rule_struct *rulestruct;

/* Init the Prelude sub system. */

void PreludeInit( _SaganConfig *config ) 
{

int ret; 

prelude_client_flags_t flags;

ret = prelude_thread_init(NULL);

if ( ret < 0 ) { 
	removelockfile(config); 
	sagan_log(config, 1, "[%s, line %d] %s: Unable to init the Prelude thread subsystem: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
	}

ret = prelude_init(NULL, NULL);
if ( ret < 0 ) {
        removelockfile(config);
        sagan_log(config, 1, "[%s, line %d] %s: Unable to init the Prelude library: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        }

ret = prelude_client_new(&preludeclient, config->sagan_prelude_profile ? config->sagan_prelude_profile : DEFAULT_ANALYZER_NAME);

if ( ret < 0 ) {
        removelockfile(config);
        sagan_log(config, 1, "[%s, line %d] %s: Unable to create a Prelude client object: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        }

flags = PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER;
ret = prelude_client_set_flags(preludeclient, prelude_client_get_flags(preludeclient) | flags);

if ( ret < 0 ) {
        removelockfile(config);
        sagan_log(config, 1, "[%s, line %d] %s: Unable to set asynchronous send and timer: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        }

setup_analyzer(prelude_client_get_analyzer(preludeclient));

ret = prelude_client_start(preludeclient);
if ( ret < 0 ) {
        removelockfile(config);
        sagan_log(config, 1, "[%s, line %d] %s: Unable to initialize Prelude client: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        }


}

/* Setup's up the Prelude analyzer.  This is information like model, 
 * class, etc */

int setup_analyzer(idmef_analyzer_t *analyzer)
{
        int ret;
        prelude_string_t *string;

        ret = idmef_analyzer_new_model(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, ANALYZER_MODEL);

        ret = idmef_analyzer_new_class(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, ANALYZER_CLASS);

        ret = idmef_analyzer_new_manufacturer(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

        ret = idmef_analyzer_new_version(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, VERSION);


        return 0;
}

int add_int_data( _SaganConfig *config, idmef_alert_t *alert, const char *meaning, uint32_t data)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *ad;

        ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
        if ( ret < 0 )
                return ret;

        idmef_additional_data_set_integer(ad, data);

        ret = idmef_additional_data_new_meaning(ad, &str);
        if ( ret < 0 ) {
                sagan_log(config, 0,"%s: error creating additional-data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }

        ret = prelude_string_set_ref(str, meaning);
        if ( ret < 0 ) {
                sagan_log(config, 0, "%s: error setting integer data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }

        return 0;
}


/****************************************************************************/
/* sagan_prelude() - This is the sub/thread called from the main process    */
/****************************************************************************/

void sagan_prelude( SaganEvent *Event ) 
{

pthread_mutex_t prelude_mutex = PTHREAD_MUTEX_INITIALIZER;

int ret;

int sid=0;
int rev=0;

idmef_message_t *idmef;
idmef_alert_t *alert;
idmef_classification_t *class;
prelude_string_t *str;

/* IDMEF message init */

ret = idmef_message_new(&idmef);
if ( ret < 0 ) {
         prelude_client_destroy(preludeclient, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
         sagan_log(Event->config, 1, "[%s, line %d] Error in idmef_message_new(). Aborting", __FILE__, __LINE__);
         }

ret = idmef_message_new_alert(idmef, &alert);
      if ( ret < 0 ) { 
	 sagan_log(Event->config, 0, "[%s, line %d] Error in idmef_message_new_alert()", __FILE__, __LINE__); 
	 goto err;
	 }

ret = idmef_alert_new_classification(alert, &class);
      if ( ret < 0 ) {
	 sagan_log(Event->config, 0, "[%s, line %d] Error in idmef_alert_new_classification()", __FILE__, __LINE__);
	 goto err;
	 }
ret = idmef_classification_new_text(class, &str);
      if ( ret < 0 ) {
         sagan_log(Event->config, 0, "[%s, line %d] Error in idmef_classification_new_text()", __FILE__, __LINE__);
	 goto err;
	 }

prelude_string_set_ref(str, rulestruct[Event->found].s_msg );

ret = event_to_impact(Event->config, rulestruct[Event->found].s_pri, alert);
      if ( ret < 0 ) {
         sagan_log(Event->config, 0, "[%s, line %d] event_to_impact() failed", __FILE__, __LINE__);
         goto err;
         }

ret = event_to_reference(rulestruct[Event->found].s_sid, class);
      if ( ret < 0 ) {
         sagan_log(Event->config, 0, "[%s, line %d] event_to_reference() failed", __FILE__, __LINE__);
         goto err;
         }

ret = event_to_source_target(Event->config, Event->ip_src, Event->ip_dst, Event->src_port, Event->dst_port, rulestruct[Event->found].ip_proto, alert);
      if ( ret < 0 ) {
         sagan_log(Event->config, 0, "[%s, line %d] event_to_source_target() failed", __FILE__, __LINE__);
         goto err;
         }

sid = atoi(rulestruct[Event->found].s_sid);
rev = atoi(rulestruct[Event->found].s_rev);

ret = syslog_to_data(Event->config, rulestruct[Event->found].s_sid, rulestruct[Event->found].s_rev, rulestruct[Event->found].ip_proto, Event->message, alert);
      if ( ret < 0 ) {
         sagan_log(Event->config, 0, "[%s, line %d] syslog_to_data() failed", __FILE__, __LINE__);
         goto err;
         }

prelude_client_send_idmef(preludeclient, idmef);

err:
idmef_message_destroy(idmef);

}

/* Assigns severity to an event.  For example,  priority 1 == High */

int event_to_impact(_SaganConfig *config, int pri, idmef_alert_t *alert) 
{

int ret;
idmef_impact_t *impact;
idmef_impact_severity_t severity;
idmef_assessment_t *assessment;

ret = idmef_alert_new_assessment(alert, &assessment);
      if ( ret < 0 ) sagan_log(config, 1, "[%s, line %d] Error in idmef_alert_new_assessment(). Abort.", __FILE__, __LINE__);

ret = idmef_assessment_new_impact(assessment,  &impact);
      if ( ret < 0 ) sagan_log(config, 1,"[%s, line %d] Error in idmef_assessment_new_impact(). Abort.", __FILE__, __LINE__);

if ( pri == 1 ) severity = IDMEF_IMPACT_SEVERITY_HIGH;
else if ( pri == 2 ) severity = IDMEF_IMPACT_SEVERITY_MEDIUM;
else if ( pri == 3 ) severity = IDMEF_IMPACT_SEVERITY_LOW;
else  severity = IDMEF_IMPACT_SEVERITY_INFO;

idmef_impact_set_severity(impact, severity);
return 0;

}


int event_to_reference(char *sid , idmef_classification_t *class)
{
int ret;
prelude_string_t *str;

ret = idmef_classification_new_ident(class, &str);
      if ( ret < 0 ) return ret; 

ret = prelude_string_sprintf(str, "%s", sid);
if ( ret < 0 ) return ret; 

ret = add_sagan_reference(class, sid); 

return ret;
}

/* Supply target/source/port information */

int event_to_source_target( _SaganConfig *config, char *ip_src, char *ip_dst, int src_port, int dst_port, int proto, idmef_alert_t *alert)
{

int ret;
idmef_source_t *source;
idmef_service_t *service;
prelude_string_t *string;
idmef_node_t *node;
idmef_address_t *address;
idmef_target_t *target;


ret = idmef_alert_new_source(alert, &source, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;

ret = idmef_source_new_interface(source, &string);
if ( ret < 0 ) return ret;

prelude_string_set_ref(string, config->sagan_interface);

ret = idmef_source_new_service(source, &service);
if ( ret < 0 ) return ret;

idmef_service_set_port(service, src_port );
if ( ret < 0 ) return ret;

idmef_service_set_ip_version(service, 4);
idmef_service_set_iana_protocol_number(service, proto);

ret = idmef_source_new_node(source, &node);
if ( ret < 0 ) return ret;

ret = idmef_node_new_address(node, &address, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;

ret = idmef_address_new_address(address, &string);
if ( ret < 0 ) return ret;

prelude_string_set_ref(string, ip_src);

ret = idmef_alert_new_target(alert, &target, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;

ret = idmef_target_new_interface(target, &string);
if ( ret < 0 ) return ret;

ret = idmef_target_new_service(target, &service);
if ( ret < 0 ) return ret;

/* Target */
idmef_service_set_port(service, dst_port);
if ( ret < 0 ) return ret;

idmef_service_set_ip_version(service, 4);
idmef_service_set_iana_protocol_number(service, proto );

ret = idmef_target_new_node(target, &node);
if ( ret < 0 ) return ret;

ret = idmef_node_new_address(node, &address, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;

ret = idmef_address_new_address(address, &string);
if ( ret < 0 ) return ret;

prelude_string_set_ref(string, ip_dst);

return 0;
}

int syslog_to_data ( _SaganConfig *config,  char *sid,  char *rev, int proto, char *message, idmef_alert_t *alert )
{

int i;

i = atoi(sid);
add_int_data(config, alert, "sagan_rule_sid", i);
i = atoi(rev);
add_int_data(config, alert, "sagan_rule_rev", i );

add_int_data(config, alert, "ip_ver", 4);

add_int_data(config, alert, "ip_proto", proto);


add_byte_data(config, alert, "payload", message, strlen(message));


return 0;
}

/* Setup for the payload information */

int add_byte_data( _SaganConfig *config , idmef_alert_t *alert, const char *meaning, const unsigned char *data, size_t size)
{

int ret;
prelude_string_t *str;
idmef_additional_data_t *ad;

ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;

ret = idmef_additional_data_set_byte_string_ref(ad, data, size);
if ( ret < 0 )  { 
	sagan_log(config, 0, "[%s, line %d] %s Error setting byte string data: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
  	return -1;
	}

ret = idmef_additional_data_new_meaning(ad, &str);
if ( ret < 0 )  {
        sagan_log(config, 0, "[%s, line %d] %s Error creating additional-data meaning: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        return -1;
	}

ret = prelude_string_set_ref(str, meaning);
if ( ret < 0 )  {
        sagan_log(config, 0, "[%s, line %d] %s Error setting byte string data meaning: %s", __FILE__, __LINE__, prelude_strsource(ret), prelude_strerror(ret));
        return -1;
	}

return 0;
}

int add_sagan_reference(idmef_classification_t *class, char *sid)
{

int ret; 
int i;
prelude_string_t *str;
idmef_reference_t *ref;

i = atol(sid);

if ( i != 0 ) { 

ret = idmef_classification_new_reference(class, &ref, IDMEF_LIST_APPEND);
if ( ret < 0 ) return ret;   

ret = idmef_reference_new_name(ref, &str);
if ( ret < 0 ) return ret;

idmef_reference_set_origin(ref, IDMEF_REFERENCE_ORIGIN_VENDOR_SPECIFIC);
ret = prelude_string_sprintf(str, "%s", sid);
if ( ret < 0 ) return ret;

ret = idmef_reference_new_meaning(ref, &str);
if ( ret < 0 ) return ret;

ret = prelude_string_sprintf(str, "Sagan Signature ID");
if ( ret < 0 ) return ret;

ret = idmef_reference_new_url(ref, &str);
if ( ret < 0 ) return ret;

ret = prelude_string_sprintf(str, ANALYZER_SID_URL "%s", sid);
return ret;
   }

return(0);

}

#endif
