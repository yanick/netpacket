
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "Module::Build" => "0.3601"
  },
  "configure_requires" => {
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "assemble/disassemble network packets at the protocol level",
  "dist_author" => [
    "Tim Potter <tpot\@samba.org>",
    "Stephanie Wehner <atrak\@itsx.com>",
    "Yanick Champoux <yanick\@cpan.org>"
  ],
  "dist_name" => "NetPacket",
  "dist_version" => "1.4.2",
  "license" => "artistic_2",
  "module_name" => "NetPacket",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "constant" => 0,
    "strict" => 0,
    "vars" => 0,
    "warnings" => 0
  },
  "script_files" => [],
  "test_requires" => {
    "File::Spec" => 0,
    "IO::Handle" => 0,
    "IPC::Open3" => 0,
    "Test::More" => "0.88"
  }
);


unless ( eval { Module::Build->VERSION(0.4004) } ) {
  my $tr = delete $module_build_args{test_requires};
  my $br = $module_build_args{build_requires};
  for my $mod ( keys %$tr ) {
    if ( exists $br->{$mod} ) {
      $br->{$mod} = $tr->{$mod} if $tr->{$mod} > $br->{$mod};
    }
    else {
      $br->{$mod} = $tr->{$mod};
    }
  }
}

my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
