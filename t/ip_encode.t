use strict;
use warnings;

use Test::More tests => 3;

use NetPacket::IP;
use NetPacket::Ethernet;

my $datagram  =  join '', map { chr } split ':', join ':' => <DATA>;

my $eth = NetPacket::Ethernet->decode( $datagram );

my $ip = NetPacket::IP->decode( $eth->{data} );

is $ip->{flags} => 2;

my $q = NetPacket::IP->decode( $ip->encode );

is $q->{flags} => $ip->{flags};

my $ip2 = NetPacket::IP->new(
	src_ip => '96.6.121.42',
	dest_ip => '192.168.2.11',
	ttl => 56,
	proto => NetPacket::IP::IP_PROTO_TCP,
	flags => NetPacket::IP::IP_FLAG_DONTFRAG,
	id => 44545,
	data => pack('H*', '005011b9fbe49b83c5d3480250101ee63dbd0000000000000000')
);

# normally checksum calculation is done by encode()
$ip2->checksum();

# omit the frame from comparison
delete $ip->{_frame};

is_deeply($ip2, $ip, "packet constructor compare");

__DATA__
0:25:209:6:219:108:0:19:163:164:237:251:8:0:69:0:0:46
174:1:64:0:56:6:248:228:96:6:121:42:192:168:2:11:0:80
17:185:251:228:155:131:197:211:72:2:80:16:30:230:61:189
0:0:0:0:0:0:0:0
