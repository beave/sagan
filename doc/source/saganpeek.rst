Sagan Peek
==========

What is "saganpeek"
-------------------

``saganpeek`` is a utility that allows you to "peek" into Sagan memory.  The utility reads
the Sagan ``mmap()`` files.  It displays the data Sagan is currently using for ``after``, 
``threshold``, ``flexbits`` and ``xbits``.  This information can be useful in debugging Sagan
or simply to view what values are currently in memory.  Running ``saganpeek`` from the command 
line without any flags will show all "active" data in memory. 

** Note: ``saganpeek`` will not display data in Redis.  For example,  if you are using
Redis for ``xbits`` or ``flexbits``, this data will not be displayed**


``saganpeek`` --help flags::

   --[ saganpeek help ]---------------------------------------------------------

   -t, --type      threshold, after, xbit, track, all (default: all)
   -h, --help      This screen.
   -i, --ipc       IPC source directory. (default: /var/sagan/ipc)

Building "saganpeek"
--------------------

After building Sagan, simply change into the ``tools/`` directory and run ``make`` and then
``make install``.  

