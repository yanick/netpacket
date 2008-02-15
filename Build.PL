use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'NetPacket',
    dist_version        => '0.05',
    create_makefile_pl  => 'passthrough',
);

$builder->create_build_script();
