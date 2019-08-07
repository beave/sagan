ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = sagan
                               sagan_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       sagan_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               sagan_SOURCES = sagan.c \
                                                       classifications.c \
						       config-yaml.c \
                                                       lockfile.c \
                                                       references.c \
                                                       rules.c \
                                                       signal-handler.c \
                                                       key.c \
                                                       stats.c \
                                                       usage.c \
                                                       plog.c \
                                                       output.c \
                                                       processor.c \
                                                       gen-msg.c \
                                                       liblognormalize.c \
                                                       ignore-list.c \
                                                       tracking-syslog.c \
                                                       send-alert.c \
                                                       credits.c \
                                                       protocol-map.c \
                                                       geoip.c \
                                                       meta-content.c \
                                                       redis.c \
                                                       flexbit.c \
                                                       flexbit-mmap.c \
						       xbit.c \
						       xbit-mmap.c \
						       xbit-redis.c \
                                                       flow.c\
                                                       aetas.c \
                                                       ipc.c \
                                                       util.c \
						       after.c \
						       threshold.c \
                                                       util-time.c \
						       input-pipe.c \
						       input-json.c \
						       input-json-map.c \
						       message-json-map.c \
                                                       util-strlcpy.c \
                                                       util-strlcat.c \
                                                       util-base64.c \
						       json-handler.c \
                                                       parsers/ip.c \
                                                       parsers/port.c \
                                                       parsers/proto.c \
                                                       parsers/hash.c \
                                                       parsers/strstr-asm/strstr-hook.c \
                                                       parsers/strstr-asm/strstr_sse2.S \
                                                       parsers/strstr-asm/strstr_sse4_2.S \
                                                       output-plugins/alert.c \
						       output-plugins/fast.c \
                                                       output-plugins/esmtp.c \
                                                       output-plugins/external.c \
                                                       output-plugins/unified2.c \
                                                       output-plugins/snortsam-twofish.c \
                                                       output-plugins/snortsam.c \
                                                       output-plugins/syslog-handler.c \
						       output-plugins/eve.c \
                                                       processors/engine.c \
                                                       processors/track-clients.c \
                                                       processors/bluedot.c \
                                                       processors/blacklist.c \
                                                       processors/perfmon.c \
						       processors/client-stats.c \
                                                       processors/bro-intel.c \
						       processors/dynamic-rules.c


                                                       install-data-local:

