CC = gcc
PROGRAM = sagan-gtk
PROGRAM_FILES = sagan-gtk.c

CFLAGS	+= -g 
LDFLAGS	+= -g
LIBS 	+=
GTKFLAGS := $(shell pkg-config --cflags --libs gtk+-2.0 gthread-2.0)

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) $(GTKFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)

