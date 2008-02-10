#
# NetPacket::TCP - Decode and encode TCP (Transmission Control
# Protocol) packets. 
#
# Comments/suggestions to tpot@acsys.anu.edu.au
#
# $Id: TCP.pm,v 1.9 1999/04/25 01:42:00 tpot Exp $
#

package NetPacket::TCP;

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

    @EXPORT_OK = qw(tcp_strip
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(tcp_strip)],  
);

}

#
# Strip header from packet and return the data contained in it
#

undef &tcp_strip;
*tcp_strip = \&strip;

sub strip {
    my ($pkt, @rest) = @_;

    my $tcp_obj = NetPacket::TCP->decode($pkt);
    return $tcp_obj->{data};
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

    # Decode TCP packet

    if (defined($pkt)) {
	my $tmp;

	($self->{src_port}, $self->{dest_port}, $self->{seqnum}, 
	 $self->{acknum}, $tmp, $self->{winsize}, $self->{cksum}, 
	 $self->{urg}, $self->{options}) =
	     unpack("nnNNnnnna*", $pkt);

	# Extract flags
	
	$self->{hlen} = $tmp >> 12;
	$self->{reserved} = $tmp & 0x0fc0 >> 6;
	$self->{flags} = $tmp & 0x003f;
	
	# Decode variable length header and remaining data

	my $olen = $self->{hlen} - 5;
	$olen = 0, if ($olen < 0);  # Check for bad hlen

	($self->{options}, $self->{data}) = unpack("a" . $olen . 
						   "a*", $self->{options});
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
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

C<NetPacket::TCP> - Assemble and disassemble TCP (Transmission Control
Protocol) packets.

=head1 SYNOPSIS

  use NetPacket::TCP;

  $tcp_obj = NetPacket::TCP->decode($raw_pkt);
  $tcp_pkt = NetPacket::TCP->encode(params...);   # Not implemented
  $tcp_data = NetPacket::TCP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::TCP> provides a set of routines for assembling and
disassembling packets using TCP (Transmission Control Protocol).  

=head2 Methods

=over

=item C<NetPacket::TCP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::TCP-E<gt>encode(param =E<gt> value)>

Return a TCP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::TCP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the TCP
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::TCP> object consists of
the following fields.

=over

=item src_port

The source TCP port for the packet.

=item dest_port

The destination TCP port for the packet.

=item seqnum

The TCP sequence number for this packet.

=item acknum

The TCP acknowledgement number for this packet.

=item hlen

The header length for this packet.

=item reserved

The 6-bit "reserved" space in the TCP header.

=item flags

Contains the urg, ack, psh, rst, syn and fin flags for this packet.

=item winsize

The TCP window size for this packet.

=item cksum

The TCP checksum.

=item urg

The TCP urgent pointer.

=item options

Any TCP options for this packet in binary form.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

tcp_strip

=item tags

The following tags group together related exportable items.

=over

=item C<:strip>

Import the strip function C<tcp_strip>.

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script is a primitive pop3 sniffer.

  #!/usr/bin/perl

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $tcp_obj = NetPacket::TCP->decode(ip_strip(eth_strip($pkt)));

      if (($tcp_obj->{src_port} == 110) or ($tcp_obj->{dest_port} == 110)) {
	  print($tcp_obj->{data});
      }
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'tcp');

=head1 TODO

=over

=item Implement encode() function

=item Assembly of TCP fragments into a data stream

=item Option processing

=item Nicer processing of TCP flags

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
