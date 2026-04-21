use strict;
use warnings;
use Config;
use FindBin;
use File::Spec;
use Test::More;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'lib');

use Overnet::Test::SpecConformance qw(
  run_irc_adapter_map_conformance
  run_irc_adapter_derived_presence_conformance
  run_irc_adapter_authoritative_conformance
);

run_irc_adapter_map_conformance();
run_irc_adapter_derived_presence_conformance();
run_irc_adapter_authoritative_conformance();

done_testing;
