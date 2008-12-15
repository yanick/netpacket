use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'NetPacket',
    dist_version_from   => 'lib/NetPacket.pm',
    create_makefile_pl  => 'passthrough',
);

$builder->create_build_script();
