#
# NetPacket - Base class for NetPacket::* object hierarchy.
#
# Comments/suggestions to tpot@acsys.anu.edu.au
#
# $Id: NetPacket.pm,v 1.5 1999/04/25 01:44:49 tpot Exp $
#

package NetPacket;

#
# Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
# the participants in the CRC for Advanced Computational Systems
# ('ACSys').
#
# ACSys makes this software and all associated data and documentation
# ('Software') available free of charge.  You may make copies of the 
# Software but you must include all of this notice on any copy.
#
# The Software was developed for research purposes and ACSys does not
# warrant that it is error free or fit for any purpose.  ACSys
# disclaims any liability for all claims, expenses, losses, damages
# and costs any user may incur as a result of using, copying or
# modifying the Software.
#

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

my $myclass;
BEGIN {
    $myclass = __PACKAGE__;
    $VERSION = "0.01";
}
sub Version () { "$myclass v$VERSION" }

BEGIN {
    @ISA = qw(Exporter);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
);

}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket> - modules to assemble/disassemble network packets at the
protocol level.

=head1 SYNOPSIS

    # NetPacket is a base class only

=head1 DESCRIPTION

C<NetPacket> provides a base class for a cluster of modules related to
decoding and encoding of network protocols.  Each C<NetPacket>
descendent module knows how to encode and decode packets for the
network protocol it implements.  Consult the documentation for the
module in question for protocol-specific implementation.

Note that there is no inheritance in the C<NetPacket::> cluster of
modules other than each protocol module being a C<NetPacket>.  This
was seen to be too restrictive as imposing inheritance relationships
(for example between the IP, UDP and TCP protocols) would make things
like tunneling or other unusual situations difficult.

=head1 WRITING YOUR OWN C<NetPacket::> MODULE

You are encouraged to write additional C<NetPacket::> modules as well
as improve existing ones.  Contact the maintainer of the module in
question with your suggestions or changes.

The following sections are a list of suggestions and conventions for
writing a C<NetPacket::> module.

=head2 Naming Conventions

When creating a module in the C<NetPacket::> namespace, it is suggested
that you stick to a couple of conventions when naming packet contents.
This will hopefully lead to a consistent namespace making the
C<NetPacket::> easier to use.

Content names are all lowercase, with underscores separating multiple
words.  The following abbreviations are recommended:

	    Word		Abbreviation
	    --------------------------------
	    source		src
	    destination		dest
	    checksum		cksum
	    identifier		id
	    version		ver
	    protocol		proto	       

=head2 Required Methods

encode(), decode(), strip()

=head2 Required Fields

Every NetPacket:: object should have the following fields.

=over

=item _parent

A link to the parent C<NetPacket::> object in which this
C<NetPacket::> object is encaulated.  This field is undefined if there
is no parent object.

=item _frame

A copy of the raw data of the packet.

=item data

This field should contain the data encapsulated in the packet (i.e any
headers or trailers stripped off) or undef if the packet contains no
data.  Note that in this sense, "data" is taken to mean information
not relevant to the particular protocol being decoded.  For example,
an ARP packet contains many header fields but no data.  A UDP datagram,
however contains header fields and a payload.

=back

=head2 Tags

=head1 COPYRIGHT

  Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
  the participants in the CRC for Advanced Computational Systems
  ('ACSys').

  ACSys makes this software and all associated data and documentation
  ('Software') available free of charge.  You may make copies of the 
  Software but you must include all of this notice on any copy.

  The Software was developed for research purposes and ACSys does not
  warrant that it is error free or fit for any purpose.  ACSys
  disclaims any liability for all claims, expenses, losses, damages
  and costs any user may incur as a result of using, copying or
  modifying the Software.


=head1 AUTHOR

Tim Potter E<lt>tpot@acsys.anu.edu.auE<gt>

=cut

# any real autoloaded methods go after this line
