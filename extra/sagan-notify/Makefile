CC = gcc
PROGRAM = sagan-notify
PROGRAM_FILES = sagan-notify.c

CFLAGS	+= -g 
LDFLAGS	+= -g
LIBS 	+= -lnotify
GTKFLAGS := $(shell pkg-config --cflags gtk+-2.0 glib-2.0) 

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) $(GTKFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)

