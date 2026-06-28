use strictures 2;
use Test::More;
use JSON ();
use Config;
use FindBin;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});

use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;
my $fixtures_dir = File::Spec->catdir(_spec_root(), 'fixtures', 'irc');

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep { /\.json$/mx } readdir $dh;
closedir $dh;

for my $file (@fixture_files) {
  my $path = File::Spec->catfile($fixtures_dir, $file);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;

  my $fixture = JSON::decode_json($json);
  my $desc = $fixture->{description};
  my $input = $fixture->{input};
  my $expected = $fixture->{expected};

  subtest "$file - $desc" => sub {
    my $result = $adapter->map_input(%{$input});

    is $result->{valid}, $expected->{overnet_valid},
      "valid = $expected->{overnet_valid}";

    if ($expected->{overnet_valid}) {
      my $got_event = { %{$result->{event}} };
      my $expected_event = { %{$expected->{event}} };

      my $got_content = delete $got_event->{content};
      my $expected_content = delete $expected_event->{content};

      is_deeply $got_event, $expected_event, 'mapped event envelope matches fixture';
      is_deeply JSON::decode_json($got_content), JSON::decode_json($expected_content),
        'mapped event content matches fixture semantically';
    } else {
      is $result->{reason}, $expected->{reason}, 'reason matches fixture';
    }
  };
}

done_testing;

sub _spec_root {
  for my $dir (
    File::Spec->catdir($FindBin::Bin, '..', '..', '..', 'spec'),
    File::Spec->catdir($FindBin::Bin, '..', '..', 'spec'),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    return $abs if -d $abs;
  }

  die "Can't locate spec root\n";
}
