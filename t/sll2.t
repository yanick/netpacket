use strict;
use warnings;

use Test2::Bundle::More;

use NetPacket::SLL2 qw/ :strip :types /;
use NetPacket::Ethernet qw/ :types /;
use NetPacket::ARP qw/ :protos /;

my @test_data = (
  {proto => ETH_TYPE_IP(), interface => 2, htype => ARPHRD_ETHER(), type => SLL_TYPE_SENT_BY_US(), src_addr => 'fedcba987654', data => "\x01\x02\x03\x04"},
);

my @datagrams = map { chomp; length($_) ? join('', map { chr hex } split /\./) : () } <DATA>;

foreach my $datagram (@datagrams) {
  my $test = shift @test_data;

  my $sll = NetPacket::SLL2->decode($datagram);
  is $sll->{proto}, $test->{proto}, 'proto';
  is $sll->{interface}, $test->{interface}, 'interface';
  is $sll->{htype}, $test->{htype}, 'htype';
  is $sll->{type}, $test->{type}, 'type';
  is lc($sll->{src_addr}), $test->{src_addr}, 'src_addr';
  is $sll->{data}, $test->{data}, 'data';
  is sll2_strip($datagram), $test->{data}, 'strip';

  my $q = NetPacket::SLL2->decode($sll->encode);
  is $q->{proto}, $sll->{proto}, 'round-trip proto';
  is $q->{interface}, $sll->{interface}, 'round-trip interface';
  is $q->{htype}, $sll->{htype}, 'round-trip htype';
  is $q->{type}, $sll->{type}, 'round-trip type';
  is lc($q->{src_addr}), lc($sll->{src_addr}), 'round-trip src_addr';
  is $q->{data}, $sll->{data}, 'round-trip data';
}


done_testing;

__DATA__
08.00.00.00.00.00.00.02.00.01.04.06.FE.DC.BA.98.76.54.00.00.01.02.03.04
