

/*

processor perfmonitor: time=300 file=/var/log/sagan/sagan.stats

Totals are "since last write" .  We'll need to subtract current verses old? 


utime, 						Current time
counters->sagantotal 				Total Event
counters->saganfound				Signatures Matched
counters->alert_total				Total Alerts
counters->after_total				After Total
counters->threshold_total			Threshold Total
counters->sagan_processor_drop			Dropped (Due to errors)
counters->ignore_count				Ignored (on purpose)

#ifdef HAVE_LIBGEOIP

No "if" needed here 

counters->geoip_lookup,				Total lookups
counters->geoip_hit				Geo hits
counters->geoip_miss				Geo miss

#endif 


total = counters->sagantotal / seconds		Avg. per "time" (time=300)

counters->sagan_processor_drop			Processor Drop
counters->blacklist_hit_count			Blacklist "hits"
counters->search_case_hit_count			Search "hit" count
counters->search_nocase_hit_count		Search "hit" count (nocase)

counters->track_clients_client_count		Number of clients tracked	(static)
counters->track_clients_down			Number of clients "down" 	(static)

counters->sagan_output_drop			Output dropped

#ifdef HAVE_LIBESMTP
if ( config->sagan_esmtp_flag ) { 

counters->esmtp_count_success			Successful SMTP
counters->esmtp_count_failed			Failed SMTP

} 
#endif

if (config->syslog_src_lookup) {

counters->dns_cache_count			Total DNS Cached entries
counters->dns_miss_count			DNS misses

}

#ifdef WITH_WEBSENSE
if (config->websense_flag) { 

counters->websense_cache_count			Websense Cache Count
counters->websense_cache_hit			Hits from Websense Cache
counters->websense_ignore_hit			Ignored (on purpose)
counters->websense_error_count			Websense Errors
counters->websense_postive_hit			Hits in logs

}
#endif

*/

