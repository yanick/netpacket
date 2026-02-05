use strict;
use warnings;

use Test2::Bundle::More;

use NetPacket::SLL qw/ :strip :types /;
use NetPacket::Ethernet qw/ :types /;
use NetPacket::ARP qw/ :protos /;

is SLL_TYPE_SENT_BY_US() => 4, 'imports';

is NetPacket::SLL::SLL_TYPE_UNICAST() => 0, 'with namespace';

my @test_data = (
  {type => SLL_TYPE_SENT_BY_US(), htype => ARPHRD_ETHER(), src_addr => 'fedcba987654', proto => ETH_TYPE_IP(), data => "\x01\x02\x03\x04"},
);

my @datagrams = map { chomp; length($_) ? join('', map { chr hex } split /\./) : () } <DATA>;

foreach my $datagram (@datagrams) {
  my $test = shift @test_data;

  my $sll = NetPacket::SLL->decode($datagram);
  is $sll->{type}, $test->{type}, 'type';
  is $sll->{htype}, $test->{htype}, 'htype';
  is lc($sll->{src_addr}), $test->{src_addr}, 'src_addr';
  is $sll->{proto}, $test->{proto}, 'proto';
  is $sll->{data}, $test->{data}, 'data';
  is sll_strip($datagram), $test->{data}, 'strip';

  my $q = NetPacket::SLL->decode($sll->encode);
  is $q->{type}, $sll->{type}, 'round-trip type';
  is $q->{htype}, $sll->{htype}, 'round-trip htype';
  is lc($q->{src_addr}), lc($sll->{src_addr}), 'round-trip src_addr';
  is $q->{proto}, $sll->{proto}, 'round-trip proto';
  is $q->{data}, $sll->{data}, 'round-trip data';
}


done_testing;

__DATA__
00.04.00.01.00.06.FE.DC.BA.98.76.54.00.00.08.00.01.02.03.04
