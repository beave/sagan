CC = gcc
PROGRAM = sagan-peek
PROGRAM_FILES = sagan-peek.c ../src/util-time.c ../src/util.c ../src/parsers/strstr-asm/strstr-hook.c ../src/lockfile.c

CFLAGS	+= -I../src -g -D_GNU_SOURCE=1 `pkg-config --cflags libfastjson libbsd`
LDFLAGS	+= -g   
LIBS 	+= -lrt `pkg-config --libs libfastjson libbsd`

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)

