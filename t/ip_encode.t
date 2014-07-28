use strict;
use warnings;

use Test::More tests => 4;

use NetPacket::IP qw(:protos :flags);
use NetPacket::Ethernet;
use NetPacket::TCP;

my $datagram  =  join '', map { chr } split ':', join ':' => <DATA>;

my $eth = NetPacket::Ethernet->decode( $datagram );

my $ip = NetPacket::IP->decode( $eth->{data} );

is $ip->{flags} => 2;

my $q = NetPacket::IP->decode( $ip->encode );

is $q->{flags} => $ip->{flags};

my $tcp = NetPacket::TCP->decode( $ip->{data} );

my $tcp2 = NetPacket::TCP->new(
	src_port => 80,
	dest_port => 4537,
	flags => ACK,
	seqnum => 4226063235,
	data => "\x00\x00\x00\x00\x00\x00",
	winsize => 7910,
	acknum => 3318958082,
);

my $ip2 = NetPacket::IP->new(
	src_ip => '96.6.121.42',
	dest_ip => '192.168.2.11',
	ttl => 56,
	proto => IP_PROTO_TCP,
	flags => IP_FLAG_DONTFRAG,
	id => 44545,
	payload => $tcp2,
);

# don't care _frame since new() can't populate this
delete $tcp->{_frame};

is_deeply($tcp2, $tcp, "deep compare decoded/constructed tcp");

is $ip2->encode(), $ip->encode(), "serialized compare decoded/constructed ip";

__DATA__
0:25:209:6:219:108:0:19:163:164:237:251:8:0:69:0:0:46
174:1:64:0:56:6:248:228:96:6:121:42:192:168:2:11:0:80
17:185:251:228:155:131:197:211:72:2:80:16:30:230:61:189
0:0:0:0:0:0:0:0
