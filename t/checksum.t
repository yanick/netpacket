use strict;
use warnings;

use Test::More tests => 4;

use NetPacket::TCP;
use NetPacket::UDP;

my $ip = { 
	src_ip => scalar gethostbyname('127.0.0.1'),
	dest_ip => scalar gethostbyname('192.168.0.1'),
};

bless $ip, 'NetPacket::IP';

my $tcp = {
	dest_port => 22,
	src_port => 13,
	seqnum => 1,
	acknum => 2,
	winsize => 32,
	urg => 0,
	hlen => 5,
	flags => 0,
	reserved => 0,
	options => '',
	data => "DEADBEEF",
};

bless $tcp, 'NetPacket::TCP';

is NetPacket::TCP::checksum( $tcp, $ip ) => 25303;

$tcp->{data} = "DEADBEEF\x01";

# force recomputation
delete $tcp->{cksum};

my $odd_checksum = NetPacket::TCP::checksum( $tcp, $ip );

is $odd_checksum => 25046, 'TCP padding done correctly';

my $udp = {
	src_port => 13,
	dest_port => 14,
	len => 8 + 7,
	data => "foo\x00\x00\x00\x00",
};

bless $udp, 'NetPacket::UDP';

is NetPacket::UDP::checksum( $udp, $ip ) => 60058, 'UDP padding';

my $udp2 = NetPacket::UDP->new(
	src_port => 13,
	dest_port => 14,
	data => "foo\x00\x00\x00\x00",
);

my $ip2 = NetPacket::IP->new(
	src_ip => '127.0.0.1',
	dest_ip => '192.168.0.1',
	payload => $udp
);

is $udp2->checksum( $ip2 ) => 60058, 'UDP padding (redux)';

