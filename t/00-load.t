use strictures 2;
use Test2::V0;

my $module = 'Overnet::Adapter::IRC';
my $path   = $module =~ s{::}{/}gr . '.pm';
my $loaded = eval {
  require $path;
  1;
};
ok $loaded, "$module loads"
  or diag $@;

my $adapter = Overnet::Adapter::IRC->new({});
isa_ok $adapter, ['Overnet::Adapter::IRC'], 'hashref constructor';

done_testing;
