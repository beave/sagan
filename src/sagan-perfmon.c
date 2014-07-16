/*


sagan.conf
processor perfmonitor: time=300 file=/var/log/sagan/sagan.stats

################################ Perfmon stop: pid=2274 at=Wed Jul 16 03:45:17 2014 (1405482317) ###################################
################################ Perfmon start: pid=7310 at=Wed Jul 16 03:45:31 2014 (1405482331) ###################################


Totals are "since last write" .  We'll need to subtract current verses old? 

utime, 						Current time			engime.utime,
counters->sagantotal 				Total Event			engine.total, 
counters->saganfound				Signatures Matched		engine.sig_match.total, 
counters->alert_total				Total Alerts			engine.alerts.total, 
counters->after_total				After Total			engine.after.total, 
counters->threshold_total			Threshold Total			engine.threshold.total, 
counters->sagan_processor_drop			Dropped (Due to errors)		engine.drop.total,
counters->ignore_count				Ignored (on purpose)		engine.ignored.total,

total = counters->sagantotal / seconds          Avg. per "time" (time=300)	engine.eps		(Total, not within "time")

#ifdef HAVE_LIBGEOIP

No "if" needed here 

counters->geoip_lookup,				Total lookups			geoip.lookup.total,
counters->geoip_hit				Geo hits			geoip.hits, 
counters->geoip_miss				Geo miss			geoip.misses,

#endif 


counters->sagan_processor_drop			Processor Drop 			processor.drop.total, 
counters->blacklist_hit_count			Blacklist "hits"		processor.blacklist.hits, 
counters->search_case_hit_count			Search "hit" count		processor.search.case.hits, 
counters->search_nocase_hit_count		Search "hit" count (nocase)	processor.search.nocase.hits, 

counters->track_clients_client_count		Number of clients tracked	processor.tracker.total	(static)
counters->track_clients_down			Number of clients "down" 	processor.tracker.down  (static)

counters->sagan_output_drop			Output dropped			output.drop.total

#ifdef HAVE_LIBESMTP
if ( config->sagan_esmtp_flag ) { 

counters->esmtp_count_success			Successful SMTP			processor.esmtp.success
counters->esmtp_count_failed			Failed SMTP			processor.esmtp.failed

} 
#endif

if (config->syslog_src_lookup) {

counters->dns_cache_count			Total DNS Cached entries	dns.total
counters->dns_miss_count			DNS misses			dns.miss

}

#ifdef WITH_WEBSENSE
if (config->websense_flag) { 

counters->websense_cache_count			Websense Cache Count		processor.websense.cache_count
counters->websense_cache_hit			Hits from Websense Cache	processor.websense.hits
counters->websense_ignore_hit			Ignored (on purpose)		processor.websense.ignored
counters->websense_error_count			Websense Errors			processor.websense.errors
counters->websense_postive_hit			Hits in logs			processor.websense.found (?)

}
#endif

*/

