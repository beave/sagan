High Performance Considerations
===============================

Depending on your hardware, Sagan can operate comfortably up to about 5k "events per/second" (EPS)
using default configurations.  When you hit this level and higher,  there are a few configuration
options to take into consideration. 

batch-size
~~~~~~~~~~

The most important thing is the ``batch-size`` sagan.yaml configuration option.  By default, 
when Sagan receives a log line,  the data is sent to any available thread.  Due to memory protections
(pthread mutex lock/unlock), this isn't efficient.   The system starts to spend more time protecting the
memory location of the single line of log data than processing the log line.  

The ``batch-size`` allows Sagan to send more data to worker threads and use less "locks".  For example, 
with a ``batch-size`` of 10,  Sagan can send 10 times more data with only one "lock" being applied.  At
even higher rates,  you may want to consider setting the ``batch-size`` to 100. 

The default batch sizes are 1 to 100.  On very high performance systems (100k+ EPS or more), you may 
want to consider rebuilding to handled even larger batches.  To do this,  you would edit the 
`sagan-defs.h` and change the following. 

::

   #define MAX_SYSLOG_BATCH        100 


To

::
 
   #define MAX_SYSLOG_BATCH        1000


Then rebuild Sagan and set your ``batch-size`` to 1000.  While you will save CPU,  you will 
use more memory.  If you sent the `MAX_SYSLOG_BATCH` to 1000 and only set the ``batch-size`` to 
100,  Sagan will still allocate memory for 1000 log lines.  In fact,  it will do the per-thread!
Think of it this way:

::
   Threads * ( MAX_MAX_SYSLOG_BATCH * 10240 bytes ) = Total memory usage.

The default allocation per log line is 10240 bytes. 


Rule sets
~~~~~~~~~

At high rates,  consideration should be taken in the rules that you are loading.  Unneeded and
unused rules waste CPU.  

If you are writing rules,  make sure you use simple rule keywords first (``content``, ``meta_content``,
``program``, etc) before moving to more complex rule options like ``pcre``.  The more simple rule
keywords can be used to "short circuit" a rule before it has to more complex operations.




