AUTOMAKE_OPIONS=foreign no-dependencies

                bin_PROGRAMS = sagan
                               sagan_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       sagan_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               sagan_SOURCES = sagan.c \
                                                       sagan-classifications.c \
						       sagan-yaml.c \
                                                       sagan-lockfile.c \
                                                       sagan-references.c \
                                                       sagan-rules.c \
                                                       sagan-signal.c \
                                                       sagan-key.c \
                                                       sagan-stats.c \
                                                       sagan-strlcat.c \
                                                       sagan-strlcpy.c \
                                                       sagan-usage.c \
                                                       sagan-util.c \
                                                       sagan-plog.c \
                                                       sagan-output.c \
                                                       sagan-processor.c \
                                                       sagan-gen-msg.c \
                                                       sagan-liblognorm.c \
                                                       sagan-ignore-list.c \
                                                       sagan-send-alert.c \
                                                       sagan-credits.c \
                                                       sagan-protocol-map.c \
                                                       sagan-geoip2.c \
                                                       sagan-meta-content.c \
                                                       sagan-xbit.c \
                                                       sagan-check-flow.c\
                                                       sagan-aetas.c \
                                                       sagan-ipc.c \
						       sagan-json.c \
                                                       parsers/parse-ip.c \
                                                       parsers/parse-port.c \
                                                       parsers/parse-proto.c \
                                                       parsers/parse-hash.c \
                                                       parsers/sagan-strstr/sagan-strstr-hook.c \
                                                       parsers/sagan-strstr/strstr_sse2.S \
                                                       parsers/sagan-strstr/strstr_sse4_2.S \
                                                       output-plugins/sagan-alert.c \
						       output-plugins/sagan-fast.c \
                                                       output-plugins/sagan-esmtp.c \
                                                       output-plugins/sagan-external.c \
                                                       output-plugins/sagan-unified2.c \
                                                       output-plugins/sagan-twofish.c \
                                                       output-plugins/sagan-snortsam.c \
                                                       output-plugins/sagan-syslog.c \
						       output-plugins/sagan-eve.c \
                                                       processors/sagan-engine.c \
                                                       processors/sagan-track-clients.c \
                                                       processors/sagan-report-clients.c \
                                                       processors/sagan-bluedot.c \
                                                       processors/sagan-blacklist.c \
                                                       processors/sagan-perfmon.c \
                                                       processors/sagan-bro-intel.c \
						       processors/sagan-dynamic-rules.c


                                                       install-data-local:

