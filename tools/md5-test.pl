#!/usr/bin/perl -w

use strict;
use lib qw'./lib ../lib';
use Digest::Perl::MD5;
use Digest::MD5;

*pmd5 = \&Digest::Perl::MD5::md5_hex;
*xmd5 = \&Digest::MD5::md5_hex;
my ($count,$bytes) = 0;

my $mult = 10;

$SIG{INT} = sub{ print "\n$count rounds\n$bytes Bytes\n"; exit; };

$|++;
while(1) {
	my $s = gen();
	my ($p,$x) = (pmd5($s),xmd5($s));
	if ($p ne $x) {
		print "\nFailure\n",
		      'Source: ',unpack('H*',$s),"\n",
		      "pmd5  : $p\n",
		      "xmd5  : $x\n";
              exit;
	} else {
    	print "ok ";
    }
    $count++; $bytes+=length $s;
}

sub gen {
	my $x;
	for (1 .. 1 + rand($count*$mult)) {
		$x .= pack 'C', rand 256;
	}
	$x;
}
