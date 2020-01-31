/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* Unlike rsyslog & syslog-ng,  NXLog (http://nxlog.co) does not 
** natively handle named pipes/fifo's.  Attempts at using the om_file 
** didn't work very well.  This small program uses NXLog's "om_exec" to 
** properly deal with FIFO input/output.  It sets the FIFO size to the 
** max (MAX_FIFO_SIZE) and writes data as it is received to the FIFO 
** in a non-blocking format.  In your nxlog.conf,  add a output module
** like this:

<Output sagan_network>
    Module om_exec
    Command /usr/local/bin/nxfifo
    Arg /var/sagan/fifo/sagan-network.fifo
</Output>

** Replace "/var/sagan/fifo/sagan-network.fifo" with your FIFO location
**
** To build this program,  simply type "make nxfifo". 
**
**/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define MAX_FIFO_SIZE 1048576
#define BUFFER_SIZE 10240

/* Globals */

int fd;

/* Prototypes */

void sig_handler(int sig);

int main(int argc, char **argv)
{

    int current_fifo_size;
    int fd_results;

    char input[BUFFER_SIZE+1] = { 0 };

    signal(SIGINT,  sig_handler);
    signal(SIGHUP,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGBUS,  sig_handler);
    signal(SIGALRM, sig_handler);
    signal(SIGSTOP, sig_handler);
    signal(SIGSEGV, sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    if ( argc != 2 )
        {
            fprintf(stderr, "Error:  No FIFO specified!\n");
            exit(-1);
        }

    fd = open(argv[1], O_RDWR);

    if ( fd < 0 )
        {
            fprintf(stderr, "Cannot open %s. Abort\n", argv[1]);
            exit(-1);
        }


    current_fifo_size = fcntl(fd, F_GETPIPE_SZ);
    fd_results = fcntl(fd, F_SETPIPE_SZ, MAX_FIFO_SIZE);
    fcntl(fd, F_SETFL, O_NONBLOCK);

    printf("The %s fifo was %d, not set to %d\n", argv[1], current_fifo_size, MAX_FIFO_SIZE);

    while(1)
        {


            if ( !fgets(input, BUFFER_SIZE, stdin))
                {
                    fprintf(stderr, "Error getting input\n");
                    exit(-1);
                };

            write(fd, input, strlen(input));

        }

}

void sig_handler(int sig)
{
    fprintf(stderr, "\nCaught signal %d\n", sig);
    close(fd);
    exit(0);
}


