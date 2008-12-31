use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'NetPacket',
    dist_version_from   => 'lib/NetPacket.pm',
    create_makefile_pl  => 'passthrough',   
    meta_merge => {
        resources => {
            repository => 'git://github.com/yanick/netpacket.git',
            bugtracker =>
            'http://rt.cpan.org/NoAuth/Bugs.html?Dist=NetPacket',
        },
    },

);

$builder->create_build_script();
