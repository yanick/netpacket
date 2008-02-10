#
# NetPacket::ICMP -Decode and encode ICMP (Internet Control Message
# Protocol) packets.
#
# Comments/suggestions to tpot@acsys.anu.edu.au
#
# $Id: ICMP.pm,v 1.7 1999/04/07 02:18:18 tpot Exp $
#

package NetPacket::ICMP;

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
    @ISA = qw(Exporter NetPacket);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(icmp_strip
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(icmp_strip)],
);

}

#
# Decode the packet
#

sub decode {
    my $class = shift;
    my($pkt, $parent, @rest) = @_;
    my $self = {};

    # Class fields

    $self->{_parent} = $parent;
    $self->{_frame} = $pkt;

    # Decode ICMP packet

    if (defined($pkt)) {

	($self->{type}, $self->{code}, $self->{cksum}, $self->{data}) =
	    unpack("CCna*", $pkt);
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip a packet of its header and return the data
#

undef &icmp_strip;
*icmpstrip = \&strip;

sub strip {
    my ($pkt, @rest) = @_;

    my $icmp_obj = decode($pkt);
    return $icmp_obj->data;
}

#
# Encode a packet
#

sub encode {
    die("Not implemented");
}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket::ICMP> - Assemble and disassemble ICMP (Internet Control
Message Protocol) packets. 

=head1 SYNOPSIS

  use NetPacket::ICMP;

  $icmp_obj = NetPacket::ICMP->decode($raw_pkt);
  $icmp_pkt = NetPacket::ICMP->encode(params...);   # Not implemented
  $icmp_data = NetPacket::ICMP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::ICMP> provides a set of routines for assembling and
disassembling packets using ICMP (Internet Control Message Protocol). 

=head2 Methods

=over

=item C<NetPacket::ICMP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::IGMP-E<gt>encode(param =E<gt> value)>

Return an IGMP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::IGMP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the ICMP
packet.

=back

=head2 Instance data

The instance data for the C<NetPacket::ICMP> object consists of
the following fields.

=over

=item type

The ICMP message type of this packet.

=item code

The ICMP message code of this packet.

=item cksum

The checksum for this packet.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

none

=item tags

The following tags group together related exportable items.

=over

=item C<:strip>

Import the strip function C<icmp_strip>.

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

=head1 TODO

=over

=item Implement encode() function

=item Create constants

=item Write example

=back

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
