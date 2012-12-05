#!/usr/bin/perl

## ossec-sagan.pl --
## This utility takes a series of OSSEC rules, and generates a series of compatible SAGAN rules. 
## Originally developed by Michael Iverson.
##
## Copyright (c) 2009-2011, Quadrant Information Security
## All rights reserved.
##
## Please submit any custom rules or ideas sagan-sigs@quadrantsec.com mailing list
##
##*************************************************************
##  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
##  following conditions are met:
##
##  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
##    disclaimer.
##  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
##    following disclaimer in the documentation and/or other materials provided with the distribution.
##  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
##    from this software without specific prior written permission.
##
##  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
##  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
##  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
##  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
##  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
##  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
##*************************************************************
##
## History:
## v0.1 2010-12-27 - Initial version
##

# Does not like the format of the XML groupnames when used as hash keys, so use strict is out.
#use strict;
#use warnings;
#use diagnostics;

use XML::Simple;    # used to manage config file in XML format
#use Data::Dumper;   # For debugging of data structures

## Define default configuration settings. 
## These can be overridden by command line options. 
##
# Input file
my $inputFile = "";

# temporary file
my $tempFile = "/tmp/ossec-rules.tmp";

# This defined the default OSSEC alert level. 
# Rules with levels <= this number are commented out by default.
my $commentLevel = "4";

## Open temporary file, and write a header to it.
##
open my $TEMPFILE, ">", "$tempFile" or 
    die "$tempFile Error: Can't open temporary file: $!\n";
print $TEMPFILE "<rules>\n";

## Read command line parameters, and process xml files passed to the  
##
my $p;
while ($p = shift) {

    # if we specify a comment level
    if (($p eq "-c") || ($p eq '--comment')) {
	$commentLevel = shift;
    }
    elsif (($p eq '-h') || ($p eq '--help')) {
	
	# Print usage instructions
	die q{Usage: 
    ossec-sagan.pl [OPTION] [FILES]

Summary: 
  Convert the supplied list of OSSEC xml rule files into a monolithic block of SAGAN
  rules. Converted rules are written to stdout. 

Options:
    -c n or --config n
         Comment out alerts with OSSEC levels less than or equal to n. (default is 4)
    -h or --help
         Print help message. 
    Note: Options must appear BEFORE file arguments.

}
	
    }
    else {
	
	# Assume that the parameter is an OSSEC xml rule file
	# we'll read in each one, and process out unnecessary tags that might get us in trouble.
	# output will be written to the temporary file.
	$inputFile = $p;

        # Check the input file for obvious issues.
        #
	die "$inputFile Error: Input file does not exist.\n" 
	    if (!(-e $inputFile));
	die "$inputFile Error: Input file is not the correct type.\n" 
	    if (!(-f $inputFile));
	die "$inputFile Error: Input file is not readable.\n" 
	    if (!(-r $inputFile));
#	die "$inputFile Error: Output directory does not exist.\n" 
#	    if (!(-d $outFolder));

        # Open up our input file.
        #
	open my $INFILE, "<", "$inputFile" or 
	    die "$inputFile Error: Can't open input file: $!\n";
	
	# read through file, only matching relevant lines
	while (<$INFILE>) {

	    # We need to add the filename to the group name, since XML:Simple can't handle
            # duplicate hash keys
	    s/<group name=\"/<group name=\"$inputFile:/; 

	    # only print relevant keys.
	    print $TEMPFILE $_ if ($_ =~ /(<\/?rule|<group name|<description|^ *<\/group>)/);
	}

	close $INFILE;
    }
}


## Close temporary file, but write trailer to it first.
##
print $TEMPFILE "</rules>\n";
close $TEMPFILE;


## Read in preprocessed XML rules from temporary file 
##
my $xmltree = XML::Simple->new();
my $cfg = $xmltree->XMLin($tempFile,ForceArray => ['description','rule']);

# debug data structure
#print Dumper($cfg);

## Print header
##
print q{##
## OSSEC SAGAN RULES (autogenerated)
##
## Sagan is:
## Copyright (c) 2009-2010, Quadrant Information Security.
## All rights reserved.
##
## Please submit any custom rules or ideas to sagan-submit@quadrantsec.com or the sagan-sigs mailing list
##
##*************************************************************
##  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
##  following conditions are met:
##
##  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
##    disclaimer.
##  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
##    following disclaimer in the documentation and/or other materials provided with the distribution.
##  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
##    from this software without specific prior written permission.
##
##  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
##  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
##  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
##  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
##  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
##  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
##*************************************************************
##  These rules were autogenerated from ossec rules using the ossec-sagan.pl script.
##  OSSEC and its supplied rules are:  
##
##  Copyright (C) 2009 Trend Micro Inc.
##  All rights reserved.
##
##  This program is a free software; you can redistribute it
##  and/or modify it under the terms of the GNU General Public
##  License (version 2) as published by the FSF - Free Software
##  Foundation.
##
##  License details: http://www.ossec.net/en/licensing.html
##
};


## For each group... 
foreach my $group ( keys %{$cfg->{'group'}} ) {

    # Strip the annoying comma from the group name.
    my $tmpgrp = $group;
    $tmpgrp =~ s/,$//;
    
    # Keep groups neatly separated in output file
    print "\n\n## Rule group: $tmpgrp\n##\n";

    # debug data structure.
    #print Dumper($cfg->{'group'}->{$group});
    
    # For each rule within the group...
    foreach my $rule ( keys %{$cfg->{'group'}->{$group}->{'rule'}} ) {
	
	# Sample SAGAN Rule
        # alert syslog $EXTERNAL_NET any -> $HOME_NET any (msg: "[OSSEC] Alert Level 5"; content: "Alert Level: 5;"; classtype: system-event; program: ossec; sid: 6000001; rev:1;)

	# Assign the alert level to a local variable, as we will use it a lot.
	my $level =  $cfg->{'group'}->{$group}->{'rule'}->{$rule}->{'level'};
	
	# check if the level is beneath the comment threshold. If it is, comment it out
        # We'll print the level number in the comment to make it easy to remove comments later.
	print "#(Level $level) " if ($level <= $commentLevel);

	# print beginning of the rule, including description (ossec can have multiple description lines)
	print "alert syslog \$EXTERNAL_NET any -> \$HOME_NET any (msg: \"[OSSEC] Level $level - ";
	foreach my $desc (@{$cfg->{'group'}->{$group}->{'rule'}->{$rule}->{'description'}}) {
	    print "$desc";
	}

	# print group name
	print " ($tmpgrp)\"; ";

	# classify rule based on OSSEC priority level
	print "content: \"Rule: $rule \"; classtype: ";
	if ($level == 0) {
	    print "tcp-connection; ";
	}
	elsif ($level < 5) {
	    print "not-suspicious; ";
	}
	elsif ($level < 10) {
	    print "system-event; ";
	}
	else {
	    print "exploit-attempt; ";
	}
	
	# embed the ossec id in the sid of the rule
	printf "program: ossec; sid: 6%06s; rev:1;)\n", $rule;
	
    }
    
}



