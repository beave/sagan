#!/usr/bin/perl -w

#
# Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
# Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

##############################################################################
# qdee - (Pronounced - "Q Dee").  This program collects IDS/IPS (and syslog!)
# events from a Cisco device using the SDEE protocol.  Events sucked off the
# Cisco device are then sent to a syslog.  Sagan can then use it's rules to 
# detect the events
#
# Written By Champ Clark III (cclark@quadrantsec.com)
# Largely based off of "ids_sdee" (unknown author)
##############################################################################

use WWW::Curl::Easy; 
use XML::Simple;
use Data::Dumper;
use Sys::Syslog qw(:standard :extended :macros);
use strict; 

# Cisco IPS username/password
#
my $username="USERNAME";
my $password="PASSWORD"; 
my $cisco_ip="10.1.1.11"; 


my $url="https://$cisco_ip/cgi-bin/sdee-server"; 
my $user_agent="Sagan_QDEE/1.0"; 
my $cookiesfile = "/tmp/qdee.$$.cookies";
my $debug=0;


##############################################################################
# Syslog settings
##############################################################################

my $syslog_remote="127.0.0.1"; 
my $syslog_port=514; 
my $syslog_program="qdee";

my $xml; 
my $headers;
my $myheaders;
my $useragent;
my $data;
my $j=0;
my $msgvalue;
my $body;

$SIG{'INT'} = 'catch_signal';
$SIG{'ABRT'} = 'catch_signal';
$SIG{'QUIT'} = 'catch_signal';
$SIG{'TERM'} = 'catch_siganl';

$xml = new XML::Simple;

print "[*] Getting subscription\n"; 

our $subscriptionId = openSubscription();

print "[*] Subscription ID: $subscriptionId.\n"; 
print "[*] Collecting events from $cisco_ip.\n"; 


my $curl = WWW::Curl::Easy->new();

while (1) { 

my $uri = "?sessionCookies&subscriptionId=$subscriptionId&maxNbrOfEvents=60&timeout=2";
my $body=""; 
my $msg="";

  open($myheaders, ">", \$headers);
  my $code = $curl->setopt(CURLOPT_USERAGENT, $useragent);

  $code = $curl->setopt(CURLOPT_COOKIEJAR, $cookiesfile);
  $code = $curl->setopt(CURLOPT_COOKIEFILE, $cookiesfile);
  $code = $curl->setopt(CURLOPT_FOLLOWLOCATION, 1);
  $code = $curl->setopt(CURLOPT_MAXREDIRS, 10);
  $code = $curl->setopt(CURLOPT_URL, "$url$uri");
  $code = $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);
  $code = $curl->setopt(CURLOPT_USERPWD, "$username:$password");
  $code = $curl->setopt(CURLOPT_WRITEHEADER, $myheaders );
  $code = $curl->setopt(CURLOPT_FILE, \$body);
  $code = $curl->setopt(CURLOPT_WRITEFUNCTION, \&chunk );
  $code = $curl->setopt(CURLOPT_CONNECTTIMEOUT, 0);

 $curl->perform();
 close($myheaders);
  my $err = $curl->errbuf;
  if ($err) { 
     print "[E] $err\n";
     exit(1);
     }

  if ($debug) { print "[D] BODY: $body\n"; }
  $data = $xml->XMLin($body);
  if ($debug) { print "[D] DUMPER: " . Dumper($data); }

##############################################################################
# Syslog/Health/Other data
##############################################################################

  if ( $data->{'env:Body'}{'sd:events'}{'evStatus'} ) { 
  
     if ( ref($data->{'env:Body'}{'sd:events'}{'evStatus'}) eq "ARRAY" ) {
          if ( $debug ) { print "[D] Syslog data is in a ARRAY.\n"; }
	  for my $in (@{ $data->{'env:Body'}{'sd:events'}{'evStatus'}} ) {

	  # Make sure data is in the array then send it.
	  if ($data->{'env:Body'}{'sd:events'}{'evStatus'}[$j]) 
	     { 
	     $msgvalue = getEventType($data->{'env:Body'}{'sd:events'}{'evStatus'}[$j]); 
	     }
	  $j++; 
	  }
	
	} else {
	if ( $debug ) { print "[D] Syslog data is in a HASH.\n"; }
	$msgvalue = getEventType($data->{'env:Body'}{'sd:events'}{'evStatus'});
	}
  }

##############################################################################
# IDS/IPS data
##############################################################################
  
  if ( $data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'} ) { 

     if ( ref($data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'}) eq "ARRAY" ) {
          if ( $debug ) { print "[D] IDS/IPS data is in a ARRAY\n"; }
          for my $in (@{ $data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'}} ) {

          # Make sure data is in the array then send it.
          if ($data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'}[$j])
             {
             $msgvalue = getEventType($data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'}[$j]);
             }
          $j++;
          }

        } else {
        if ( $debug ) { print "[D] IDS/IPS data is in a HASH\n"; }
        $msgvalue = getEventType($data->{'env:Body'}{'sd:events'}{'sd:evIdsAlert'});
        }
  }

  if ($msgvalue) { 
     setlogsock( {  type => "udp", port => $syslog_port, host => $syslog_remote } );
     openlog($syslog_program, 'ndelay', 'user');
     syslog('info', $msgvalue);
     closelog();
     $msgvalue="";
     }
}

##############################################################################
# getEventType - Determines if an event is health, syslog, IDS/IPS, etc. 
# It then formats a message to stuff into syslog
##############################################################################

sub getEventType { 
my $data = shift;
my $msgreturn = ""; 

# Health

if ( $data->{'healthAndSecurity'} ) { 
   
   print "[*] Got Health/Status event.\n"; 
   $msgreturn = "Health_Status: $data->{'healthAndSecurity'}{'warning'}{'metricStatus'}{'status'} , Health Warning: $data->{'healthAndSecurity'}{'warning'}{'metricStatus'}{'name'} , Timezone: $data->{'time'}{'timeZone'}, Time_Content: $data->{'time'}{'content'} , Time_Offset: $data->{'time'}{'offset'} , Originator_appInstanceId: $data->{'originator'}{'appInstanceId'} , Originator_appName: $data->{'originator'}{'appName'} , Originator_hostID: $data->{'originator'}{'hostId'} , EventID: $data->{'eventId'} , Vendor: $data->{'vendor'}";
   return($msgreturn);
   }

# Syslog

if ( $data->{'syslogMessage'} ) { 
   
   print "[*] Got Syslog event.\n"; 
   $msgreturn = "Syslog_Message: \"$data->{'syslogMessage'}{'description'}\" , Timezone: $data->{'time'}{'timeZone'} , Time_Content: $data->{'time'}{'content'} , Time_Offset: $data->{'time'}{'offset'}";
   return($msgreturn);
   }

# IDS/IPS

if ( $data->{'sd:signature'}{'id'} ) { 

   print "[*] Got IPS/IDS event.\n"; 
   $msgreturn = "Signature_ID: $data->{'sd:signature'}{'id'} , IDS_Event_Description: \"$data->{'sd:signature'}{'description'}\" , Source: $data->{'sd:participants'}{'sd:attacker'}{'sd:addr'}{'content'}:$data->{'sd:participants'}{'sd:attacker'}{'sd:port'}  Destination: $data->{'sd:participants'}{'sd:target'}{'sd:addr'}{'content'}:$data->{'sd:participants'}{'sd:target'}{'sd:port'} , Protocol: $data->{'cid:protocol'} , Severity: $data->{'severity'} , CID_Created: $data->{'sd:signature'}{'cid:created'}, CID_Type: $data->{'sd:signature'}{'cid:type'} , CID_Version: $data->{'sd:signature'}{'cid:version'} , Event_ID: $data->{'eventId'} , Vendor: $data->{'vendor'}";
   return($msgreturn);
   }

}

##############################################################################
# openSubscription - Open and retrieves a subscription ID from the Cisco IPS
# device
##############################################################################

sub openSubscription {

  my $curl = WWW::Curl::Easy->new();
  my $myheaders;
  my $body = "";
  my $headers = "";
  my $uri = "?action=open&sessionCookies";
  open($myheaders, ">", \$headers);
  my $code = $curl->setopt(CURLOPT_USERAGENT, $useragent);
  $code = $curl->setopt(CURLOPT_COOKIEJAR, $cookiesfile);
  $code = $curl->setopt(CURLOPT_COOKIEFILE, $cookiesfile);
  $code = $curl->setopt(CURLOPT_FOLLOWLOCATION, 1);
  $code = $curl->setopt(CURLOPT_MAXREDIRS, 10);
  $code = $curl->setopt(CURLOPT_URL, "$url$uri");
  $code = $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);
  $code = $curl->setopt(CURLOPT_USERPWD, "$username:$password");
  $code = $curl->setopt(CURLOPT_WRITEHEADER, $myheaders );
  $code = $curl->setopt(CURLOPT_FILE, \$body);
  $code = $curl->setopt(CURLOPT_WRITEFUNCTION, \&chunk );
  $curl->perform();
  close($myheaders);

  my $err = $curl->errbuf;
  if ($err) { print "ERROR $err\n"; }

  if ($debug) { 
     print "[D] $body\n"; 
     }

  if ($body =~ /errLimitExceeded/) {
     print "[E] Max subscription connections reached!\n";
     print "[E] SSH into the device and run 'show stat sdee'.  Then run:\n"; 
     print "[E] links \"https://$cisco_ip/cgi-bin/sdee-server?action=close&subscriptionId={subscriptionid}\"\n"; 
     exit(1);
     }

   $data = $xml->XMLin($body);

return($data->{'env:Body'}{'sd:subscriptionId'});
}

##############################################################################
# chunk - Make data into "chunks" (append data)
##############################################################################

sub chunk { 
    my ($data,$pointer)=@_; 
    ${$pointer}.=$data; 
    return length($data) 
    }

##############################################################################
# catch_signal - Intercepts the signal (control-C, etc) and closes the
# subscription with the Cisco device
##############################################################################

sub catch_signal { 

    print "[*] Got signal! Unsubscribing \'$subscriptionId\' from $cisco_ip.\n";
    my $uri = "?action=close&subscriptionId=$subscriptionId";
    my $curl = WWW::Curl::Easy->new();


    open($myheaders, ">", \$headers);
    my $code = $curl->setopt(CURLOPT_USERAGENT, $useragent);
    $code = $curl->setopt(CURLOPT_COOKIEJAR, $cookiesfile);
    $code = $curl->setopt(CURLOPT_COOKIEFILE, $cookiesfile);
    $code = $curl->setopt(CURLOPT_FOLLOWLOCATION, 1);
    $code = $curl->setopt(CURLOPT_MAXREDIRS, 10);
    $code = $curl->setopt(CURLOPT_URL, "$url$uri");
    $code = $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);
    $code = $curl->setopt(CURLOPT_USERPWD, "$username:$password");
    $code = $curl->setopt(CURLOPT_WRITEHEADER, $myheaders );
    $code = $curl->setopt(CURLOPT_FILE, \$body);
    $code = $curl->setopt(CURLOPT_WRITEFUNCTION, \&chunk );
    $curl->perform();

    sleep(1);

    close($myheaders);
    my $err = $curl->errbuf;

    if ($err) { 
       print "[E] $err\n"; 
       exit(1);
       }

    if ($body =~ /env:Fault/) { 
       print "[E] Fault while unsubscribing! You might need to manually unsubscribe using the\n";
       print "[E] following command:\n"; 
       print "[E] links \"https://$cisco_ip/cgi-bin/sdee-server?action=close&subscriptionId=$subscriptionId\"\n";
       print "[E] Exiting!\n"; 
       exit(1);
       }
           
    sleep(1); 
    print "[*] Successfully unsubscibing and exiting.\n"; 

exit(0);
} 
