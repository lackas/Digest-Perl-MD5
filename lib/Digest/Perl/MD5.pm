#!/usr/local/bin/perl
#$Id$

require 5.004;
package Digest::Perl::MD5;
use strict;
use vars qw($VERSION @ISA @EXPORTER @EXPORT_OK);

@EXPORT_OK = qw(md5 md5_hex md5_base64);

@ISA = 'Exporter';
$VERSION = '1.1';

# I-Vektor
use constant A => 0x67_45_23_01;
use constant B => 0xef_cd_ab_89;
use constant C => 0x98_ba_dc_fe;
use constant D => 0x10_32_54_76;

# for internal use
use constant MAX  => 0xFFFFFFFF;


# padd a message to a multiple of 64
sub padding($) {
    my $msg = shift;    
    $msg .= chr(128); # ein bit ganz links
    my $l = length $msg;
    $msg .= "\0" x ( ($l % 64 < 56 ? 56 : 120) - $l % 64 );
    # this does not realy works, but no one really wants to encrypt more then 2^32 bits
    # so it does not matter
    $l = ($l-1)*8;
    $msg .= pack 'VV', $l & MAX , $l & 0x00000000;
}


#    ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
sub rotate_left($$) {
	$_[0]<<$_[1]|$_[0]>>32-$_[1]
}

sub sum(@) {
	$_[0] += $_[1];
	while ($_[0] > MAX) {$_[0] -= MAX+1}
	$_[0];  
}


sub round($$$$@) {
  my @state;
  my ($a,$b,$c,$d) = (@state[0..3],my @x) = @_;

  $a=sum(rotate_left(sum(($b&$c)|(~$b&$d),$a+$x[ 0]+0xd76aa478),7),$b);	# /* 1 */
  $d=sum(rotate_left(sum(($a&$b)|(~$a&$c),$d+$x[ 1]+0xe8c7b756),12),$a);	# /* 2 */
  $c=sum(rotate_left(sum(($d&$a)|(~$d&$b),$c+$x[ 2]+0x242070db),17),$d);	# /* 3 */
  $b=sum(rotate_left(sum(($c&$d)|(~$c&$a),$b+$x[ 3]+0xc1bdceee),22),$c);	# /* 4 */
  $a=sum(rotate_left(sum(($b&$c)|(~$b&$d),$a+$x[ 4]+0xf57c0faf),7),$b);	# /* 5 */
  $d=sum(rotate_left(sum(($a&$b)|(~$a&$c),$d+$x[ 5]+0x4787c62a),12),$a);	# /* 6 */
  $c=sum(rotate_left(sum(($d&$a)|(~$d&$b),$c+$x[ 6]+0xa8304613),17),$d);	# /* 7 */
  $b=sum(rotate_left(sum(($c&$d)|(~$c&$a),$b+$x[ 7]+0xfd469501),22),$c);	# /* 8 */
  $a=sum(rotate_left(sum(($b&$c)|(~$b&$d),$a+$x[ 8]+0x698098d8),7),$b);	# /* 9 */
  $d=sum(rotate_left(sum(($a&$b)|(~$a&$c),$d+$x[ 9]+0x8b44f7af),12),$a);	# /* 10 */
  $c=sum(rotate_left(sum(($d&$a)|(~$d&$b),$c+$x[10]+0xffff5bb1),17),$d);	# /* 11 */
  $b=sum(rotate_left(sum(($c&$d)|(~$c&$a),$b+$x[11]+0x895cd7be),22),$c);	# /* 12 */
  $a=sum(rotate_left(sum(($b&$c)|(~$b&$d),$a+$x[12]+0x6b901122),7),$b);	# /* 13 */
  $d=sum(rotate_left(sum(($a&$b)|(~$a&$c),$d+$x[13]+0xfd987193),12),$a);	# /* 14 */
  $c=sum(rotate_left(sum(($d&$a)|(~$d&$b),$c+$x[14]+0xa679438e),17),$d);	# /* 15 */
  $b=sum(rotate_left(sum(($c&$d)|(~$c&$a),$b+$x[15]+0x49b40821),22),$c);	# /* 16 */ 
  $a=sum(rotate_left(sum(($b&$d)|($c&(~$d)),$a+$x[ 1]+0xf61e2562),5),$b);	# /* 17 */
  $d=sum(rotate_left(sum(($a&$c)|($b&(~$c)),$d+$x[ 6]+0xc040b340),9),$a);	# /* 18 */
  $c=sum(rotate_left(sum(($d&$b)|($a&(~$b)),$c+$x[11]+0x265e5a51),14),$d);	# /* 19 */
  $b=sum(rotate_left(sum(($c&$a)|($d&(~$a)),$b+$x[ 0]+0xe9b6c7aa),20),$c);	# /* 20 */
  $a=sum(rotate_left(sum(($b&$d)|($c&(~$d)),$a+$x[ 5]+0xd62f105d),5),$b);	# /* 21 */
  $d=sum(rotate_left(sum(($a&$c)|($b&(~$c)),$d+$x[10]+0x2441453),9),$a);	# /* 22 */
  $c=sum(rotate_left(sum(($d&$b)|($a&(~$b)),$c+$x[15]+0xd8a1e681),14),$d);	# /* 23 */
  $b=sum(rotate_left(sum(($c&$a)|($d&(~$a)),$b+$x[ 4]+0xe7d3fbc8),20),$c);	# /* 24 */
  $a=sum(rotate_left(sum(($b&$d)|($c&(~$d)),$a+$x[ 9]+0x21e1cde6),5),$b);	# /* 25 */
  $d=sum(rotate_left(sum(($a&$c)|($b&(~$c)),$d+$x[14]+0xc33707d6),9),$a);	# /* 26 */
  $c=sum(rotate_left(sum(($d&$b)|($a&(~$b)),$c+$x[ 3]+0xf4d50d87),14),$d);	# /* 27 */
  $b=sum(rotate_left(sum(($c&$a)|($d&(~$a)),$b+$x[ 8]+0x455a14ed),20),$c);	# /* 28 */
  $a=sum(rotate_left(sum(($b&$d)|($c&(~$d)),$a+$x[13]+0xa9e3e905),5),$b);	# /* 29 */
  $d=sum(rotate_left(sum(($a&$c)|($b&(~$c)),$d+$x[ 2]+0xfcefa3f8),9),$a);	# /* 30 */
  $c=sum(rotate_left(sum(($d&$b)|($a&(~$b)),$c+$x[ 7]+0x676f02d9),14),$d);	# /* 31 */
  $b=sum(rotate_left(sum(($c&$a)|($d&(~$a)),$b+$x[12]+0x8d2a4c8a),20),$c);	# /* 32 */
  $a=sum(rotate_left(sum(($b^$c^$d),$a+$x[ 5]+0xfffa3942),4),$b);	# /* 33 */
  $d=sum(rotate_left(sum(($a^$b^$c),$d+$x[ 8]+0x8771f681),11),$a);	# /* 34 */
  $c=sum(rotate_left(sum(($d^$a^$b),$c+$x[11]+0x6d9d6122),16),$d);	# /* 35 */
  $b=sum(rotate_left(sum(($c^$d^$a),$b+$x[14]+0xfde5380c),23),$c);	# /* 36 */
  $a=sum(rotate_left(sum(($b^$c^$d),$a+$x[ 1]+0xa4beea44),4),$b);	# /* 37 */
  $d=sum(rotate_left(sum(($a^$b^$c),$d+$x[ 4]+0x4bdecfa9),11),$a);	# /* 38 */
  $c=sum(rotate_left(sum(($d^$a^$b),$c+$x[ 7]+0xf6bb4b60),16),$d);	# /* 39 */
  $b=sum(rotate_left(sum(($c^$d^$a),$b+$x[10]+0xbebfbc70),23),$c);	# /* 40 */
  $a=sum(rotate_left(sum(($b^$c^$d),$a+$x[13]+0x289b7ec6),4),$b);	# /* 41 */
  $d=sum(rotate_left(sum(($a^$b^$c),$d+$x[ 0]+0xeaa127fa),11),$a);	# /* 42 */
  $c=sum(rotate_left(sum(($d^$a^$b),$c+$x[ 3]+0xd4ef3085),16),$d);	# /* 43 */
  $b=sum(rotate_left(sum(($c^$d^$a),$b+$x[ 6]+0x4881d05),23),$c);	# /* 44 */
  $a=sum(rotate_left(sum(($b^$c^$d),$a+$x[ 9]+0xd9d4d039),4),$b);	# /* 45 */
  $d=sum(rotate_left(sum(($a^$b^$c),$d+$x[12]+0xe6db99e5),11),$a);	# /* 46 */
  $c=sum(rotate_left(sum(($d^$a^$b),$c+$x[15]+0x1fa27cf8),16),$d);	# /* 47 */
  $b=sum(rotate_left(sum(($c^$d^$a),$b+$x[ 2]+0xc4ac5665),23),$c);	# /* 48 */
  $a=sum(rotate_left(sum(($c^($b|(~$d)),$a+$x[ 0]+0xf4292244)),6),$b);	# /* 49 */
  $d=sum(rotate_left(sum(($b^($a|(~$c)),$d+$x[ 7]+0x432aff97)),10),$a);	# /* 50 */
  $c=sum(rotate_left(sum(($a^($d|(~$b)),$c+$x[14]+0xab9423a7)),15),$d);	# /* 51 */
  $b=sum(rotate_left(sum(($d^($c|(~$a)),$b+$x[ 5]+0xfc93a039)),21),$c);	# /* 52 */
  $a=sum(rotate_left(sum(($c^($b|(~$d)),$a+$x[12]+0x655b59c3)),6),$b);	# /* 53 */
  $d=sum(rotate_left(sum(($b^($a|(~$c)),$d+$x[ 3]+0x8f0ccc92)),10),$a);	# /* 54 */
  $c=sum(rotate_left(sum(($a^($d|(~$b)),$c+$x[10]+0xffeff47d)),15),$d);	# /* 55 */
  $b=sum(rotate_left(sum(($d^($c|(~$a)),$b+$x[ 1]+0x85845dd1)),21),$c);	# /* 56 */
  $a=sum(rotate_left(sum(($c^($b|(~$d)),$a+$x[ 8]+0x6fa87e4f)),6),$b);	# /* 57 */
  $d=sum(rotate_left(sum(($b^($a|(~$c)),$d+$x[15]+0xfe2ce6e0)),10),$a);	# /* 58 */
  $c=sum(rotate_left(sum(($a^($d|(~$b)),$c+$x[ 6]+0xa3014314)),15),$d);	# /* 59 */
  $b=sum(rotate_left(sum(($d^($c|(~$a)),$b+$x[13]+0x4e0811a1)),21),$c);	# /* 60 */
  $a=sum(rotate_left(sum(($c^($b|(~$d)),$a+$x[ 4]+0xf7537e82)),6),$b);	# /* 61 */
  $d=sum(rotate_left(sum(($b^($a|(~$c)),$d+$x[11]+0xbd3af235)),10),$a);	# /* 62 */
  $c=sum(rotate_left(sum(($a^($d|(~$b)),$c+$x[ 2]+0x2ad7d2bb)),15),$d);	# /* 63 */
  $b=sum(rotate_left(sum(($d^($c|(~$a)),$b+$x[ 9]+0xeb86d391)),21),$c);	# /* 64 */

  sum($state[0],$a), sum($state[1],$b), sum($state[2],$c), sum($state[3],$d);
}


# object part of this module
sub new {
	bless {}, shift;
}

sub reset {
	my $self = shift;
	delete $self->{data};
	$self
}

sub add(@) {
	my $self = shift;
	$self->{data} .= join'', @_;
	$self
}

sub addfile {
  	my $self = shift;
	my $fh = shift;
	$self->{data} .= do{local$/;<$fh>};
	$self
}

sub digest {
	md5(shift->{data})
}

sub hexdigest {
	md5_hex(shift->{data})
}

sub b64digest {
	md5_base64(shift->{data})
}

sub md5($) {
	my $message = padding(shift);
	my ($a,$b,$c,$d) = (A,B,C,D);
	for my $i (0 .. (length $message)/64-1) {
		my @X = unpack 'V16', substr($message,$i*64,64);	
		($a,$b,$c,$d) = round($a,$b,$c,$d,@X);
	}
	pack 'V4',$a,$b,$c,$d;    
}


sub md5_hex($) {  
  unpack 'H*', md5(shift);
}

sub md5_base64($) {
  encode_base64(md5(shift));
}


sub encode_base64 ($) {
    my $res;
    while ($_[0] =~ /(.{1,45})/gs) {
	$res .= substr pack('u', $1), 1;
	chop $res;
    }
    $res =~ tr|` -_|AA-Za-z0-9+/|;               # `# help emacs
    chop $res;chop $res;
    $res;
}


=head1 NAME

Digest::MD5::Perl - Perl implementation of Ron Rivests MD5 Algorithm

=head1 DISCLAIMER

This is B<not> an interface (like C<Digest::MD5>) but an Perl implementation of MD5.
It is written in perl only and because of this it is slow but it works without C-Code.
You should use C<Digest::MD5> instead of this module if it is available.
This module is only usefull for

=over 4

=item

computers where you cannot install C<Digest::MD5> (e.g. lack of a C-Compiler)

=item

encrypting only small amounts of data (less than one million bytes)

=item

educational purposes

=back

=head1 SYNOPSIS

 # Functional style
 use Digest::MD5  qw(md5 md5_hex md5_base64);

 $hash = md5 $data;
 $hash = md5_hex $data;
 $hash = md5_base64 $data;
    

 # OO style
 use Digest::MD5;

 $ctx = Digest::MD5->new;

 $ctx->add($data);
 $ctx->addfile(*FILE);

 $digest = $ctx->digest;
 $digest = $ctx->hexdigest;
 $digest = $ctx->b64digest;

=head1 DESCRIPTION

This modules has the same interface as the much faster C<Digest::MD5>. So you can
easily exchange them, e.g.

	BEGIN {
	  eval {
	    require Digest::MD5;
	    import Digest::MD5 'md5_hex'
	  };
	  if ($@) { # ups, no Digest::MD5
	    require Digest::Perl::MD5;
	    import Digest::Perl::MD5 'md5_hex'
	  }		
	}

If the C<Digest::MD5> module is available it is used and if not you take
C<Digest::Perl::MD5>.

For a detailed Documentation see the C<Digest::MD5> module.

=head1 EXAMPLES

The simplest way to use this library is to import the md5_hex()
function (or one of its cousins):

    use Digest::Perl::MD5 'md5_hex';
    print 'Digest is ', md5_hex 'foobarbaz', "\n";

The above example would print out the message

    Digest is 6df23dc03f9b54cc38a0fc1483df6e21

provided that the implementation is working correctly.  The same
checksum can also be calculated in OO style:

    use Digest::MD5;
    
    $md5 = Digest::MD5->new;
    $md5->add('foo', 'bar');
    $md5->add('baz');
    $digest = $md5->hexdigest;
    
    print "Digest is $digest\n";

=head1 LIMITATIONS

This implementation of the MD5 algorithm has some limitations:

=over 4

=item

It's slow, very slow. I've done my very best but Digest::MD5 is still 1000 times faster.
So you can only encrypt Data up to one million bytes in an acceptable time. It's usefull for
encrypting short data like passwords.

=item

You can only encrypt up to 2^32 bits = 512 MB. You should use C<Digest::MD5> for those
amounts of data.

=item

C<Digest::Perl::MD5> loads all data to encrypt into memory. This is a todo.

=back

=head1 SEE ALSO

L<Digest::MD5>

L<md5sum(1)>

RFC 1321

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

 Copyright 2000 Christian Lackas
 Copyright 1991-1992 RSA Data Security, Inc.

The MD5 algorithm is defined in RFC 1321. The basic C code
implementing the algorithm is derived from that in the RFC and is
covered by the following copyright:

=over 4

=item

Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.

=back

This copyright does not prohibit distribution of any version of Perl
containing this extension under the terms of the GNU or Artistic
licenses.

=head1 AUTHORS

The original MD5 interface was written by Neil Winton
(C<N.Winton@axion.bt.co.uk>).

C<Digest::MD5> was made by Gisle Aas <gisle@aas.no> (I took his Interface
and part of the documentation)

This release was made by Christian Lackas <delta@clackas.de>.

=cut







__END__


# this is old code. Slow but readable

sub round($$$$@) {
  my @state;
  (@state[0..3],my @x) = @_;
  my ($a,$b,$c,$d) = @state;

  FF($a, $b, $c, $d, $x[ 0], S11, 0xd76aa478); #/* 1 */
  FF($d, $a, $b, $c, $x[ 1], S12, 0xe8c7b756); #/* 2 */
  FF($c, $d, $a, $b, $x[ 2], S13, 0x242070db); #/* 3 */
  FF($b, $c, $d, $a, $x[ 3], S14, 0xc1bdceee); #/* 4 */
  FF($a, $b, $c, $d, $x[ 4], S11, 0xf57c0faf); #/* 5 */
  FF($d, $a, $b, $c, $x[ 5], S12, 0x4787c62a); #/* 6 */
  FF($c, $d, $a, $b, $x[ 6], S13, 0xa8304613); #/* 7 */
  FF($b, $c, $d, $a, $x[ 7], S14, 0xfd469501); #/* 8 */
  FF($a, $b, $c, $d, $x[ 8], S11, 0x698098d8); #/* 9 */
  FF($d, $a, $b, $c, $x[ 9], S12, 0x8b44f7af); #/* 10 */
  FF($c, $d, $a, $b, $x[10], S13, 0xffff5bb1); #/* 11 */
  FF($b, $c, $d, $a, $x[11], S14, 0x895cd7be); #/* 12 */
  FF($a, $b, $c, $d, $x[12], S11, 0x6b901122); #/* 13 */
  FF($d, $a, $b, $c, $x[13], S12, 0xfd987193); #/* 14 */
  FF($c, $d, $a, $b, $x[14], S13, 0xa679438e); #/* 15 */
  FF($b, $c, $d, $a, $x[15], S14, 0x49b40821); #/* 16 */
  
  GG ($a, $b, $c, $d, $x[ 1], S21, 0xf61e2562); #/* 17 */
  GG ($d, $a, $b, $c, $x[ 6], S22, 0xc040b340); #/* 18 */
  GG ($c, $d, $a, $b, $x[11], S23, 0x265e5a51); #/* 19 */
  GG ($b, $c, $d, $a, $x[ 0], S24, 0xe9b6c7aa); #/* 20 */
  GG ($a, $b, $c, $d, $x[ 5], S21, 0xd62f105d); #/* 21 */
  GG ($d, $a, $b, $c, $x[10], S22,  0x2441453); #/* 22 */
  GG ($c, $d, $a, $b, $x[15], S23, 0xd8a1e681); #/* 23 */
  GG ($b, $c, $d, $a, $x[ 4], S24, 0xe7d3fbc8); #/* 24 */
  GG ($a, $b, $c, $d, $x[ 9], S21, 0x21e1cde6); #/* 25 */
  GG ($d, $a, $b, $c, $x[14], S22, 0xc33707d6); #/* 26 */
  GG ($c, $d, $a, $b, $x[ 3], S23, 0xf4d50d87); #/* 27 */
  GG ($b, $c, $d, $a, $x[ 8], S24, 0x455a14ed); #/* 28 */
  GG ($a, $b, $c, $d, $x[13], S21, 0xa9e3e905); #/* 29 */
  GG ($d, $a, $b, $c, $x[ 2], S22, 0xfcefa3f8); #/* 30 */
  GG ($c, $d, $a, $b, $x[ 7], S23, 0x676f02d9); #/* 31 */
  GG ($b, $c, $d, $a, $x[12], S24, 0x8d2a4c8a); #/* 32 */

  HH ($a, $b, $c, $d, $x[ 5], S31, 0xfffa3942); #/* 33 */
  HH ($d, $a, $b, $c, $x[ 8], S32, 0x8771f681); #/* 34 */
  HH ($c, $d, $a, $b, $x[11], S33, 0x6d9d6122); #/* 35 */
  HH ($b, $c, $d, $a, $x[14], S34, 0xfde5380c); #/* 36 */
  HH ($a, $b, $c, $d, $x[ 1], S31, 0xa4beea44); #/* 37 */
  HH ($d, $a, $b, $c, $x[ 4], S32, 0x4bdecfa9); #/* 38 */
  HH ($c, $d, $a, $b, $x[ 7], S33, 0xf6bb4b60); #/* 39 */
  HH ($b, $c, $d, $a, $x[10], S34, 0xbebfbc70); #/* 40 */
  HH ($a, $b, $c, $d, $x[13], S31, 0x289b7ec6); #/* 41 */
  HH ($d, $a, $b, $c, $x[ 0], S32, 0xeaa127fa); #/* 42 */
  HH ($c, $d, $a, $b, $x[ 3], S33, 0xd4ef3085); #/* 43 */
  HH ($b, $c, $d, $a, $x[ 6], S34,  0x4881d05); #/* 44 */
  HH ($a, $b, $c, $d, $x[ 9], S31, 0xd9d4d039); #/* 45 */
  HH ($d, $a, $b, $c, $x[12], S32, 0xe6db99e5); #/* 46 */
  HH ($c, $d, $a, $b, $x[15], S33, 0x1fa27cf8); #/* 47 */
  HH ($b, $c, $d, $a, $x[ 2], S34, 0xc4ac5665); #/* 48 */

  II ($a, $b, $c, $d, $x[ 0], S41, 0xf4292244); #/* 49 */
  II ($d, $a, $b, $c, $x[ 7], S42, 0x432aff97); #/* 50 */
  II ($c, $d, $a, $b, $x[14], S43, 0xab9423a7); #/* 51 */
  II ($b, $c, $d, $a, $x[ 5], S44, 0xfc93a039); #/* 52 */
  II ($a, $b, $c, $d, $x[12], S41, 0x655b59c3); #/* 53 */
  II ($d, $a, $b, $c, $x[ 3], S42, 0x8f0ccc92); #/* 54 */
  II ($c, $d, $a, $b, $x[10], S43, 0xffeff47d); #/* 55 */
  II ($b, $c, $d, $a, $x[ 1], S44, 0x85845dd1); #/* 56 */
  II ($a, $b, $c, $d, $x[ 8], S41, 0x6fa87e4f); #/* 57 */
  II ($d, $a, $b, $c, $x[15], S42, 0xfe2ce6e0); #/* 58 */
  II ($c, $d, $a, $b, $x[ 6], S43, 0xa3014314); #/* 59 */
  II ($b, $c, $d, $a, $x[13], S44, 0x4e0811a1); #/* 60 */
  II ($a, $b, $c, $d, $x[ 4], S41, 0xf7537e82); #/* 61 */
  II ($d, $a, $b, $c, $x[11], S42, 0xbd3af235); #/* 62 */
  II ($c, $d, $a, $b, $x[ 2], S43, 0x2ad7d2bb); #/* 63 */
  II ($b, $c, $d, $a, $x[ 9], S44, 0xeb86d391); #/* 64 */
  
  return (sum($state[0],$a),sum($state[1],$b),sum($state[2],$c),sum($state[3],$d));
}

sub FF(\$$$$$$$) {
  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
  $$a = sum($$a,sum(F($b,$c,$d),$x,$ac));
  $$a = rotate_left($$a,$s);
  $$a = sum($$a,$b);
}
sub GG(\$$$$$$$) {
  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
  $$a = sum($$a, sum(G($b,$c,$d),$x,$ac)); 
  $$a = rotate_left($$a, $s);
  $$a = sum($$a,$b); 
}

sub HH(\$$$$$$$) {
  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
  $$a = sum($$a, sum(H($b,$c,$d),$x,$ac)); 
  $$a = rotate_left($$a, $s);
  $$a = sum($$a,$b); 
}

sub II(\$$$$$$$) {
  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
  $$a = sum($$a, sum(I($b,$c,$d),$x,$ac)); 
  $$a = rotate_left($$a, $s);
  $$a = sum($$a,$b); 
}
sub F($$$) {
	my ($X, $Y, $Z) = @_;
	($X & $Y) | ((~$X) & $Z)
}
sub G($$$) {
	my ($X, $Y, $Z) = @_;
	(($X & $Z) | ($Y & (~$Z)))
}
sub H($$$) {
	my ($X, $Y, $Z) = @_;
	($X ^ $Y ^ $Z) 
}
sub I($$$) {
	my ($X, $Y, $Z) = @_;
	$Y ^ ($X | (~$Z))
}

sub FF(\$$$$$$$) {
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum((($_[1] & $_[2]) | ((~$_[1]) & $_[3])),$_[4],$_[6])),$_[5]),$_[1]);
}

sub GG(\$$$$$$$) {
#  my $Z = pack'V', $_[3];
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(($_[1] & $_[3]) | ($_[2] & (~$_[3])),$_[4],$_[6])),$_[5]),$_[1]);
}

sub HH(\$$$$$$$) {
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(($_[1] ^ $_[2] ^ $_[3]),$_[4],$_[6])),$_[5]),$_[1]);
}

sub II(\$$$$$$$) {
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum($_[2] ^ ($_[1] | (~$_[3])),$_[4],$_[6])),$_[5]),$_[1]);
}

# Shift-lengths
use constant S11 => 7;
use constant S12 => 12;
use constant S13 => 17;
use constant S14 => 22;
use constant S21 => 5;
use constant S22 => 9;
use constant S23 => 14;
use constant S24 => 20;
use constant S31 => 4;
use constant S32 => 11;
use constant S33 => 16;
use constant S34 => 23;
use constant S41 => 6;
use constant S42 => 10;
use constant S43 => 15;
use constant S44 => 21;

# for debugging
sub hexdump($) {
	my $t = shift;
	for (split //,$t) {
      printf '%02x ', ord;
    }
    print "\n";
}
