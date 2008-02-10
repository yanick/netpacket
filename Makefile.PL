#!/usr/bin/perl
#
# Makefile for Net::Protocol bundle
#
# $Id: Makefile.PL,v 1.2 1998/10/08 02:42:03 tpot Exp $
#

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'NetPacket',
    DISTNAME => 'NetPacket',
    VERSION => 0.01,
    dist => {
	'COMPRESS' => 'gzip -9f',
	'SUFFIX' => 'gz'
	}
);

