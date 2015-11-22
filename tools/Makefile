CC = gcc
PROGRAM = sagan-peek
PROGRAM_FILES = sagan-peek.c

CFLAGS	+= -g 
LDFLAGS	+= -g
LIBS 	+= -lrt

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)

