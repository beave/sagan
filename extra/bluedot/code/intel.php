<?php

// Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
// Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License Version 2 as
// published by the Free Software Foundation.  You may not use, modify or
// distribute this program under any other version of the GNU General
// Public License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

// ***************************************************************************
// Bluedot "intel.php" - This does the Bluedot lookups from MariaDB/MySQL and 
// returns JSON back to the user.  
// ***************************************************************************

// Load configuration file.

include("/usr/local/bluedot/etc/bluedot-config.php");

$TYPE = 0;
$PRETTY = false;
$API_KEY = "";
$Q_QUERY = "";
$query = "";
$sqlout = "";

header("Content-Type: application/json; charset=UTF-8");

// ***************************************************************************
// Setup connection to Redis
// ***************************************************************************

$redisClient = new Redis();
$redisClient->connect( $redis_host, $redis_port, $redis_timeout ); // Giving timeOut of 3.5 sec

// ***************************************************************************
// Verify the API key
// ***************************************************************************

// If there is no apikey, abort. 

if ( !isset($_GET["apikey"]) )
	{
	Unauthorized();
	}

// Have a key, get it and look it up.

$API_KEY = Remove_Unwanted($_GET['apikey']);
$api_owner = $redisClient->get($API_KEY);

// If not found, Redis will return null . 

if ( $api_owner == "" ) 
	{
	Unauthorized();
	}

// ***************************************************************************
// Setup connection to MySQL/MariaDB
// ***************************************************************************

$pdo = new PDO('mysql:dbname='.$database.';host='.$host, $user, $password);   

// Does the user want "pretty" output?

if ( isset($_GET["pretty"]) )
	{
	$PRETTY = true;
	}

if ( isset($_GET["ip"]) )
        {
	$Q_QUERY = Remove_Unwanted($_GET['ip']);
	$TYPE = 1;
	
	$q_array = DB_Query( $pdo, $api_owner, "q_ip_rep", "ip_address", $Q_QUERY );

        }

else if ( isset($_GET["hash"]) )
        {
	$Q_QUERY = Remove_Unwanted($_GET['hash']);
        $TYPE = 2;

	$q_array = DB_Query( $pdo, $api_owner, "q_hash_rep", "hash", $Q_QUERY );
        }

else if ( isset($_GET["url"]) )
        {
	$Q_QUERY = Remove_Unwanted($_GET['url']);
        $TYPE = 3;

	$q_array = DB_Query( $pdo, $api_owner, "q_url_rep", "url", $Q_QUERY );
        }

else if ( isset($_GET["filename"]) )
        {
	$Q_QUERY = Remove_Unwanted($_GET['filename']);
        $TYPE = 4;

	$q_array = DB_Query( $pdo, $api_owner, "q_filename_rep", "filename", $Q_QUERY );
        }

else if ( isset($_GET["ja3"]) )
        {
	$Q_QUERY = Remove_Unwanted($_GET['ja3']);
        $TYPE = 5;

	$q_array = DB_Query( $pdo, $api_owner, "q_ja3_rep", "ja3", $Q_QUERY );
        }


// ***************************************************************************
// If no $TYPE is set, then the user made an invalid request. 
// ***************************************************************************

if ( $TYPE == 0 )
	{
	Unauthorized();
	}

// ***************************************************************************
// Return JSON 
// ***************************************************************************

if ( $PRETTY == true )
	{
	echo json_encode( $q_array, JSON_PRETTY_PRINT);
	} else {
	echo json_encode( $q_array );
	}

$pdo=null;	// Close MySQL connection

// ***************************************************************************
// DB_Query - This does the MySQL query for user data.
// ***************************************************************************

function DB_Query ( $pdo, $api_owner, $table, $type, $Q_QUERY ) 
{

   $code_str = "";
   $private = "no"; 
   $is_private = 0; 

   if ( $type == "ip_address" )
      {
     
         $is_private = isPublicAddress($Q_QUERY); 

	 if ( $is_private == -4 || $is_private == -16 ) 
	    {
	   $q_array = array('api_user' => $api_owner, 'code' => 0, 'category' => 'Private Network', 'comments' => 'Private Network Address', 'source' => 'none', 'ctime_epoch' => 0, 'ctime' => null, 'mtime_epoch' => 0, 'mtime' => null, 'query' => $Q_QUERY, 'query_type' => $type );
	
	   return($q_array);
	    
	    }
      }

   $rowstr = $pdo->query( "SELECT reputation,comments,rep_source,UNIX_TIMESTAMP(rep_published),UNIX_TIMESTAMP(rep_last_status),rep_published,rep_last_status,now() FROM $table where $type = '$Q_QUERY'" )->fetch();

   $reputation = intval( $rowstr["reputation"] );
   $comments = $rowstr["comments"];
   $source = $rowstr["rep_source"];
   $ctime_u = intval( $rowstr["UNIX_TIMESTAMP(rep_published)"] );
   $mtime_u = intval( $rowstr["UNIX_TIMESTAMP(rep_last_status)"] );
   $ctime = $rowstr["rep_published"]; 
   $mtime = $rowstr["rep_last_status"];
   $query_time = $rowstr["now()"];

   // Build the JSON string. 

   if ( $reputation == 0 ) 
	{
	$code_str = "Neutral";
	}

   else if ( $reputation == 1 )
	{
	$code_str = "Whitelisted";
	}

   else if ( $reputation == 2 ) 
	{
	$code_str = "Client"; 
	}

   else if ( $reputation == 3 ) 
	{
	$code_str = "Malicious";
	}

   else if ( $reputation == 4 )
	{
	$code_str = "Honeypot";
	}

   else if ( $reputation == 7 ) 
	{
	$code_str = "Advisory";
	}

   else if ( $reputation == 8 )
	{
	$code_str = "Scanners";
	}

   else if ( $reputation == 9 )
	{
	$code_str = "Tor";
	}

   else if ( $reputation == 10 )
	{
	$code_str = "Proxy";
	}


   $q_array = array('api_user' => $api_owner, 'code' => $reputation, 'category' => $code_str, 'comments' => $comments, 'source' => $source, 'ctime_epoch' => $ctime_u, 'ctime' => $ctime, 'mtime_epoch' => $mtime_u, 'mtime' => $mtime, 'query_timestamp' => $query_time, 'query' => $Q_QUERY, 'query_type' => $type ); 

   return($q_array); 

}

// 
// This is taken from https://stackoverflow.com/questions/13818064/check-if-an-ip-address-is-private
// Determines if a IP address is public or not (including IPv6).

function isPublicAddress($ip) {

  // returns false on failure.
  // negative if it's a private or special address (-4:IPv4, -16:IPv6)
  // positive if it's a common IP public address (4:IPv4, 16:IPv6)

  $networks = array(
    '4' => array('0.0.0.0/8',
      '10.0.0.0/8',
      '100.64.0.0/10',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '172.16.0.0/12',
      '192.0.0.0/24',
      '192.0.0.0/29',
      '192.0.0.8/32',
      '192.0.0.9/32',
      '192.0.0.170/32',
      '192.0.0.170/32',
      '192.0.2.0/24',
      '192.31.196.0/24',
      '192.52.193.0/24',
      '192.88.99.0/24',
      '192.168.0.0/16',
      '192.175.48.0/24',
      '198.18.0.0/15',
      '198.51.100.0/24',
      '203.0.113.0/24',
      '240.0.0.0/4',
      '255.255.255.255/32')
    ,
    '16' => array('::1/128',
      '::/128',
      '::ffff:0:0/96',
      '64:ff9b::/96',
      '100::/64',
      '2001::/23',
      '2001::/32',
      '2001:1::1/128',
      '2001:2::/48',
      '2001:3::/32',
      '2001:4:112::/48',
      '2001:5::/32',
      '2001:10::/28',
      '2001:20::/28',
      '2001:db8::/32',
      '2002::/16',
      '2620:4f:8000::/48',
      'fc00::/7',
      'fe80::/10') 
    );

    $ip = inet_pton($ip);
    if( $ip === false ) return false;

    $space='16';
    if (strlen($ip) === 4) { 
      $space='4';
    }

    //Is the IP in a private or special range?

    foreach($networks[$space] as $network) {

      //split $network in address and mask

      $parts=explode('/',$network);
      $network_address = inet_pton($parts[0]);
      $network_mask    = inet_pton( _mask( $ip , $parts[1] ) );
      if (($ip & $network_mask) === $network_address){
        return -1*$space;
      }
    }
    //Success!
    return $space;
}

function _mask($ip,$nbits){
  $mask='';
  $nibble=array('0','8','C','E');
  $f_s= $nbits >> 2 ;
  if( $f_s > 0 ) $mask.=str_repeat('F',$f_s);
  if( $nbits % 4 ) $mask.= $nibble[$nbits % 4];
  if( strlen($ip) === 4 ){
    if( strlen($mask) < 8 ) $mask.=str_repeat('0', 8 - strlen($mask) );
    long2ip('0x'.$mask);
    $mask=long2ip('0x'.$mask);
  }else{
    if( strlen($mask) < 32 ) $mask.=str_repeat('0', 32 - strlen($mask) );
    $mask=rtrim(chunk_split($mask,4,':'),':');
  }
  return $mask;
}

// ***************************************************************************
// Unauthorized() - Informs the user that they are not authenicated.
// ***************************************************************************

function Unauthorized()
{
echo "Unauthorized";
exit;
}

// ***************************************************************************
// Remove_Unwanted( $string ) - removes unwanted characters from string. Used
// For input validation.
// ***************************************************************************

function Remove_Unwanted ($string )
{
   return preg_replace('/[^A-Za-z0-9\-\:.\/ ]/', '', $string);
}

?>
