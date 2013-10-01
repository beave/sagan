
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include "sagan.h"
#include "processors/sagan-engine.h"
#include "version.h"

struct _SaganConfig *config;

void Sagan_Send_Alert ( _SaganProcSyslog *SaganProcSyslog_LOCAL, _Sagan_Processor_Info *processor_info, char *ip_src, char *ip_dst, int proto, int alertid, int src_port, int dst_port ) {

char tmp[64] = { 0 };

        struct _Sagan_Event *SaganProcessorEvent = NULL;
        SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));
        memset(SaganProcessorEvent, 0, sizeof(_SaganEvent));

        if ( processor_info->processor_generator_id != SAGAN_PROCESSOR_GENERATOR_ID ) {
        SaganProcessorEvent->f_msg           =       Sagan_Generator_Lookup(processor_info->processor_generator_id, alertid);
        } else {
        SaganProcessorEvent->f_msg           =       processor_info->processor_name;
        }
	
        SaganProcessorEvent->message         =       SaganProcSyslog_LOCAL->syslog_message;
        SaganProcessorEvent->program         =       processor_info->processor_name; 
        SaganProcessorEvent->facility        =       processor_info->processor_facility;
        SaganProcessorEvent->priority        =       processor_info->processor_priority;	/* Syslog priority */
        SaganProcessorEvent->pri             =       processor_info->processor_pri;		/* Sagan priority */
        SaganProcessorEvent->class           =       processor_info->processor_class;
        SaganProcessorEvent->tag             =       processor_info->processor_tag;
        SaganProcessorEvent->rev             =       processor_info->processor_rev;

        SaganProcessorEvent->ip_src          =       ip_src;
        SaganProcessorEvent->ip_dst          =       ip_dst;
        SaganProcessorEvent->dst_port        =       dst_port;
        SaganProcessorEvent->src_port        =       src_port;
        SaganProcessorEvent->found           =       0;


        snprintf(tmp, sizeof(tmp)-1, "%d", alertid);

        SaganProcessorEvent->sid             =       tmp;
        SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
        SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
        SaganProcessorEvent->ip_proto        =       proto;

        SaganProcessorEvent->event_time_sec  =       time(NULL);

        SaganProcessorEvent->generatorid     =       processor_info->processor_generator_id;

        Sagan_Output ( SaganProcessorEvent );
        free(SaganProcessorEvent);

}

