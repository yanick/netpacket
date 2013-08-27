use strict;
use warnings;

# this test was generated with Dist::Zilla::Plugin::Test::Compile 2.020

use Test::More 0.88;



my @module_files = (
    'NetPacket.pm',
    'NetPacket/ARP.pm',
    'NetPacket/Ethernet.pm',
    'NetPacket/ICMP.pm',
    'NetPacket/IGMP.pm',
    'NetPacket/IP.pm',
    'NetPacket/TCP.pm',
    'NetPacket/UDP.pm',
    'NetPacket/USBMon.pm'
);

my @scripts = (

);

# no fake home requested

use IPC::Open3;
use IO::Handle;
use File::Spec;

my @warnings;
for my $lib (@module_files)
{
    open my $stdout, '>', File::Spec->devnull or die $!;
    open my $stdin, '<', File::Spec->devnull or die $!;
    my $stderr = IO::Handle->new;

    my $pid = open3($stdin, $stdout, $stderr, qq{$^X -Mblib -e"require q[$lib]"});
    waitpid($pid, 0);
    is($? >> 8, 0, "$lib loaded ok");

    if (my @_warnings = <$stderr>)
    {
        warn @_warnings;
        push @warnings, @_warnings;
    }
}



is(scalar(@warnings), 0, 'no warnings found') if $ENV{AUTHOR_TESTING};



done_testing;
