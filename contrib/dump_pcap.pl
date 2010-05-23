#!/usr/bin/perl 

use strict;
use warnings;

use 5.10.0;

use Net::Pcap qw/ pcap_open_offline pcap_loop /;

my $err;
my $pcap = pcap_open_offline( shift, \$err);

pcap_loop( $pcap, -1, sub {
        my ( $user_data, $header, $packet ) = @_;

        state $packet_nbr = 1;

        say "=== packet ", $packet_nbr++;

        my $pretty = unpack "H*", $packet;

        $pretty =~ s/.{32}/$&\n/g;
        $pretty=~ s/../$& /g;

        say $pretty, "\n";

}, "foo" );


