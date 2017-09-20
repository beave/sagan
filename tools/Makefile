CC = gcc
PROGRAM = sagan-peek
PROGRAM_FILES = sagan-peek.c ../src/util-time.c ../src/util.c ../src/parsers/strstr-asm/strstr-hook.c ../src/lockfile.c ../src/util-strlcpy.c ../src/util-strlcat.c

CFLAGS	+= -I../src -g -D_GNU_SOURCE=1
LDFLAGS	+= -g   
LIBS 	+= 

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)

