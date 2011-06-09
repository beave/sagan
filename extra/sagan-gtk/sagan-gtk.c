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

/* sagan-gtk.c
 * This program is called via the Sagan configuration option 'output external:'
 * option.  Using GTK,  this creates a "popup" window when a Sagan event
 * is triggered.
 */

#include <gtk/gtk.h>
#include <pthread.h>
#include <string.h>

#define MAX_BUF 10240

static void destroy( GtkWidget *, gpointer );

int main() {

GtkWidget *window;
GtkWidget *label;

char input[MAX_BUF]="\0";
char messageit[MAX_BUF]="\0";

while (fgets(input, MAX_BUF-1, stdin)) { 
	strncat(messageit, input, MAX_BUF-1-strlen(messageit));
}

messageit[MAX_BUF-1] = '\0';	/* Avoid overflow and null terminates */

	gtk_init(NULL,NULL);
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	label = gtk_label_new(NULL);

	g_signal_connect (window, "destroy", G_CALLBACK (destroy), NULL);

	gtk_window_set_title(GTK_WINDOW(window), "Sagan Alert Message");
	gtk_label_set_markup(GTK_LABEL(label), messageit );
	gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
	gtk_container_add(GTK_CONTAINER(window), label);
	gtk_widget_show(label);

	gtk_window_set_default_size(GTK_WINDOW(window), 300, 100);
	gtk_widget_show_all(window);
	gtk_main();	
	return 0;
}

static void destroy( GtkWidget *widget, gpointer   data )
{
    gtk_main_quit ();
}

