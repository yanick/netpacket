package NetPacket::SLL;
our $AUTHORITY = 'cpan:YANICK';
# ABSTRACT: Assemble and disassemble Linux cooked capture (SLL) packets.
$NetPacket::SLL::VERSION = '1.8.0';
use strict;
use warnings;

use parent 'NetPacket';

my @sll_types = qw/ SLL_TYPE_UNICAST
                    SLL_TYPE_BROADCAST
                    SLL_TYPE_MULTICAST
                    SLL_TYPE_SENT_TO_OTHER
                    SLL_TYPE_SENT_BY_US    /;

our @EXPORT_OK = ('sll_strip', @sll_types);
our %EXPORT_TAGS = (
    ALL => [@EXPORT_OK],
    strip => [qw(sll_strip)],
    types => \@sll_types,
);

#
# SLL packet types
#

use constant SLL_TYPE_UNICAST       => 0;
use constant SLL_TYPE_BROADCAST     => 1;
use constant SLL_TYPE_MULTICAST     => 2;
use constant SLL_TYPE_SENT_TO_OTHER => 3;
use constant SLL_TYPE_SENT_BY_US    => 4;

#
# Decode the packet
#

sub decode {
    my $class = shift;
    my ($pkt, $parent) = @_;
    my $self = {};

    $self->{_parent} = $parent;
    $self->{_frame} = $pkt;

    # Decode SLL packet

    if (defined $pkt) {
        ($self->{type}, $self->{htype}, my $addr_len, $self->{src_addr},
            $self->{proto}, $self->{data}) = unpack('nnnH16na*', $pkt);

        if ($addr_len < 8) {
            $self->{src_addr} = substr($self->{src_addr}, 0, $addr_len * 2);
        }
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it
#

undef &sll_strip;
*sll_strip = \&strip;

sub strip {
    my ($pkt) = @_;

    my $sll_obj = NetPacket::SLL->decode($pkt);
    return $sll_obj->{data};
}

#
# Encode a packet
#

sub encode {
    my $self = shift;

    my $addr_len = int(length($self->{src_addr}) / 2);

    my $packet = pack('nnnH16n', $self->{type}, $self->{htype},
        $addr_len, $self->{src_addr}, $self->{proto});
    $packet .= $self->{data};

    return $packet;
}

1;

__END__

=pod

=head1 NAME

NetPacket::SLL - Assemble and disassemble Linux cooked capture (SLL) packets.

=head1 VERSION

version 1.8.0

=head1 SYNOPSIS

  use NetPacket::SLL;

  my $sll_obj = NetPacket::SLL->decode($raw_pkt);
  my $sll_pkt = $sll_obj->encode();
  my $sll_data = NetPacket::SLL::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::SLL> provides a set of routines for assembling and
disassembling packets using Linux cooked capture (libpcap SLL).
Linux cooked capture is a pseudo-link-layer used by libpcap when
capturing packets on the "any" device (because packets may have
different link layer headers) or when the native link layer headers
can't be used.

See L<https://gitlab.com/wireshark/wireshark/-/wikis/SLL> and
L<https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html> for
more details on the SLL protocol.

=head2 Methods

=over

=item C<NetPacket::SLL-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<$sll_obj-E<gt>encode()>

Return an SLL packet encoded with the instance data specified.

=back

=head2 Functions

=over

=item C<NetPacket::SLL::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the SLL
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::SLL> object consists of
the following fields.

=over

=item type

The SLL packet type.

  # SLL_TYPE_UNICAST
  0, if the packet was specifically sent to us by somebody else;
  # SLL_TYPE_BROADCAST
  1, if the packet was broadcast by somebody else;
  # SLL_TYPE_MULTICAST
  2, if the packet was multicast, but not broadcast, by somebody else;
  # SLL_TYPE_SENT_TO_OTHER
  3, if the packet was sent to somebody else by somebody else;
  # SLL_TYPE_SENT_BY_US
  4, if the packet was sent by us.

=item htype

The device type as a L<Linux ARP hardware
type|https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml>.

=item src_addr

Up to the first 8 bytes of the source link-layer address for this
packet as a hex string.

=item proto

The protocol type for the packet. Usually an ethernet protocol type,
but the meaning depends on the device type as described at
L<https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>.

=item data

The encapsulated data (payload) for this SLL packet.

=back

=head2 Exports

=over

=item default

none

=item tags

The following tags group together related exportable items.

=over

=item C<:types>

  SLL_TYPE_UNICAST SLL_TYPE_BROADCAST SLL_TYPE_MULTICAST
  SLL_TYPE_SENT_TO_OTHER SLL_TYPE_SENT_BY_US

=item C<:strip>

Import the strip function C<sll_strip>.

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script prints the source address, device type, and
protocol type of each packet to standard output.

  #!/usr/bin/perl

  use strict;
  use warnings;
  use Net::PcapUtils;
  use NetPacket::SLL;

  sub process_pkt {
      my ($user, $hdr, $pkt) = @_;
      my $sll_obj = NetPacket::SLL->decode($pkt);
      print("$sll_obj->{src_addr} $sll_obj->{htype} $sll_obj->{proto}\n");
  }

  Net::PcapUtils::loop(\&process_pkt);

=head1 COPYRIGHT

Copyright (c) 2021 Dan Book.

This module is free software.  You can redistribute it and/or
modify it under the terms of the Artistic License 2.0.

This program is distributed in the hope that it will be useful,
but without any warranty; without even the implied warranty of
merchantability or fitness for a particular purpose.

=head1 AUTHOR

Dan Book E<lt>dbook@cpan.orgE<gt>

=cut
