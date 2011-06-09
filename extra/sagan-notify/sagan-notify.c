/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-notify.c
 * This program is called via the Sagan configuration option 'output external:'
 * option.  Using libnotify,  this creates a "popup" window when a Sagan event
 * is triggered.
 */

#include <libnotify/notify.h>
#include <pthread.h>
#include <string.h>

#define MAX_BUF 10240

int main() {

char input[MAX_BUF]="\0";
char messageit[MAX_BUF]="\0";

char *title="Sagan Alert";

while (fgets(input, MAX_BUF-1, stdin)) { 
	strncat(messageit, input, MAX_BUF-1-strlen(messageit));
}

messageit[MAX_BUF-1] = '\0';	/* Avoid overflow and null terminates */

NotifyNotification *n;
notify_init("Sagan");
n = notify_notification_new (title,messageit, NULL, NULL);
notify_notification_set_timeout(n, 1000);

     if (!notify_notification_show (n, NULL)) {
        g_error("Failed to send notification.\n");
	return 1;
     }
      g_object_unref(G_OBJECT(n));

return 0;
}

 


