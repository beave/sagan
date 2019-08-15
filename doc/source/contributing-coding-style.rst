Contributing & Coding Style
===========================

How to contribute to Sagan
--------------------------

Rules & Signatures
~~~~~~~~~~~~~~~~~~

Sagan signatures are the life-blood of Sagan!  It is probably one of the most valuable ways that you
can contribute to Sagan.  If you understand the basics of how `Suricata IDS <https://suricata-ids.org>`_
or `Snort <https://snort.org>_` signatures function, then you already know how to construct Sagan rules.
If you want to add to a rule set or create an entirely new rule set, this is a huge way to contribute!

Code
~~~~

Are you a C programmer and want to add some functionality to Sagan?  That's great! You might
want to share your idea with the Sagan coding team.  This way,  if it is not an idea that will fit with 
Sagan or it is a duplicated effort,  you'll know before you dive in. The best way to contact the 
Sagan team is via the Sagan mailing list (https://groups.google.com/forum/#!forum/sagan-users). 

Also,  check the ``Coding guidelines and style`` section of this page. 

Documentation
~~~~~~~~~~~~~

Code is great but it is almost worthless without proper documentation.  Do you see something in our 
documentation that is incorrect?  Perhaps something that could be better written or explained? Feel
free to contribute! 

The Sagan documentation is part of the Sagan source tree.  We use the Python Sphinx system and 
"readthedocs.org" for publication.  

** MORE ABOUT HOW TO CONTIBUTE DOCS HERE! **


Blogs & articles
~~~~~~~~~~~~~~~~

Tell us, and better yet,  the world, how you are using Sagan.  We are always interested to see who and 
how our software is being used.  In return,  we will link to your articles from within our 
`Sagan ReadTheDocs.org <https://sagan.readthedocs.org>`_ documentation page! This help spread the word
about Sagan and we truly appreciate it!


Coding guidelines and style
---------------------------

Coding style
~~~~~~~~~~~~

Sagan development is primarily done in C.  We use the ``gnu`` "artistic style".  If you are not 
familiar with the ``gnu`` artistic style, that is okay.  We use tools like ``astyle`` to keep 
code consistent.  Using tools like ``astyle`` allows you to write code in the style you are most
comfortable with and then convert it before committing.  In fact,  it is pretty rare that the main
contributors manually follow these guidelines!

To install ``astyle``,  as root:

::

   apt-get install astyle


Before committing your code,  simply run the following command within your source tree:

::

   astyle --style=gnu --suffix=none --verbose *.c *.h

Coding Guidelines
~~~~~~~~~~~~~~~~~

While everyone has their own set styles and methods of coding,  there are a few things that we prefer
to see in the Sagan code.  The biggest thing is consistency.  Not only by the coding "style" (see 
``Coding Style``) but also logical formatting. 

Consistency with "if" statement is required.  For example:

::

   /* Incorrect */
   
   if (0 == variable ) 
      {
      ...
      }

Will be rejected.  The proper coding format with Sagan would be:

::

   /* Correct */

   if ( variable == 0 ) 
      {
      ...
      }


When using boolean operators, be sure and use the ``stdbool.h`` ``true`` and ``false``.  For example:

::

  /* Correct */

  if ( variable == true ) 
     {
     ...
     }

  /* Incorrect */

  if ( variable == 1 ) 
     {
     ...
     }

Your code should contain comments that are clear.  Proper comment syntax is desired as well.  For example:

::

  // Example incorrect comment

  if ( x == y )         /* Incorrect comment */
     {
     ...
     }

  /* Example correct comment */

  if ( x == y )         // This is acceptable
     {
     ...
     }

The ``{`` and ``}`` are converted in the GNU "artistic style".  Even if you do not prefer this formatting, 
programs like ``astyle`` can correct them before you commit.  For example:

::

  /* Incorrect */

  if ( x == y ) { 
     ...
     }

  /* Correct */

  if ( x == y ) 
     {
     ...
     }

  /* Incorrect */

  if ( x == y ) 
       b = a; 

  /* Correct */

  if ( x == y ) 
     {
       b = a; 
     }


These are a few simple rules to consider before contributing code.  In many cases ``astyle`` will address them for you.

