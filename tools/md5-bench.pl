#!/usr/local/bin/perl -w

# Benchmark
# compares Digest::Perl::MD5 and Digest::MD5

use strict;
use Benchmark;
use Digest::MD5;
use Digest::Perl::MD5;

timethese(100_000,{
	'MD5' => 'Digest::MD5::md5(q!delta!)',
	'Perl::MD5' => 'Digest::Perl::MD5::md5(q!delta!)',
});
