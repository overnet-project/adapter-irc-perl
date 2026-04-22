use strict;
use warnings;
use Test::More;
use Config;
use FindBin;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});

use_ok('Overnet::Adapter::IRC');

done_testing;
