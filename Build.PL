
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "Errno" => 0,
    "File::Spec" => 0,
    "IO::Handle" => 0,
    "IPC::Open3" => 0,
    "Module::Build" => "0.3601",
    "Test::More" => "0.88"
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
  "dist_version" => "1.4.0",
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
  "script_files" => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
