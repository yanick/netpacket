#!/usr/bin/perl
#
# Makefile for Net::Protocol bundle
#
# $Id: Makefile.PL,v 1.4 2001/07/29 23:23:42 tpot Exp $
#

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'NetPacket',
    DISTNAME => 'NetPacket',
    VERSION => 0.04,
    dist => {
	'COMPRESS' => 'gzip -9f',
	'SUFFIX' => 'gz'
	}
);

