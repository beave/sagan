#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

/* THIS IS NOT NEARLY DONE - ONLY POC CODE */

#ifdef HAVE_GTK

#include <gtk/gtk.h>
#include <stdlib.h>


// introduce the environment variable
// DISPLAY, if not present
//if (setenv ("DISPLAY", ":0", 0) == -1)
//    error ("setenv"); 

int sagan_gtk( void )
{
  GtkWidget *window;
  GtkWidget *label;

  char *alert = "[sensorname] Sagan Alert: 5000114";

  gtk_init(NULL, NULL); 		// HMMM

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_window_set_title(GTK_WINDOW(window), alert);

  char *str = "[**] [5000114] [SYSLOG] Possible unknown problem on a system [**]\n\
[Classification: program-error] [Priority: 2] \n\
2010-11-17 16:10:29 12.145.241.50:514 -> 12.145.241.55:514 local5 info \n\
Syslog message: -bash: HISTORY: PID=7339 UID=1000 corrupt \n\
[Xref => <a href=\"http://wiki.softwink.com/bin/view/Main/5000114\">http://wiki.softwink.com/bin/view/Main/5000114</a>]";


  label = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(label), str);

  gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_LEFT);
  gtk_container_add(GTK_CONTAINER(window), label);
  gtk_widget_show(label);

  gtk_window_set_default_size(GTK_WINDOW(window), 300, 100);

  g_signal_connect(window, "destroy",
      G_CALLBACK (gtk_main_quit), NULL);

  gtk_widget_show(window);

  gtk_main();

  return 0;
}


#endif



