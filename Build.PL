
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  'build_requires' => {
    'Module::Build' => '0.3601'
  },
  'configure_requires' => {
    'Module::Build' => '0.3601'
  },
  'dist_abstract' => 'assemble/disassemble network packets at the protocol level',
  'dist_author' => [
    'Yanick Champoux <yanick@cpan.org>'
  ],
  'dist_name' => 'NetPacket',
  'dist_version' => '0.43.1',
  'license' => 'artistic_2',
  'module_name' => 'NetPacket',
  'recommends' => {},
  'recursive_test_files' => 1,
  'requires' => {},
  'script_files' => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
