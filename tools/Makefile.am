ACLOCAL_AMFLAGS = -I m4

                  AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                                  bin_PROGRAMS = saganpeek
                                          saganpeek_CPPFLAGS = -I../src $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                                  saganpeek_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                                          saganpeek_SOURCES = saganpeek.c \
                                                                  ../src/util-strlcpy.c \
                                                                  ../src/util-strlcat.c \
                                                                  ../src/util.c \
                                                                  ../src/util-time.c \
                                                                  ../src/lockfile.c \
                                                                  ../src/parsers/strstr-asm/strstr-hook.c \
                                                                  ../src/parsers/strstr-asm/strstr_sse2.S \
                                                                  ../src/parsers/strstr-asm/strstr_sse4_2.S

                                                                  install-data-local:

