use strict;
use warnings;
use Test::More;
use JSON::PP;
use File::Basename;
use File::Spec;

use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;
my $fixtures_dir = File::Spec->catdir(dirname(__FILE__), '..', '..', 'overnet-spec', 'fixtures', 'irc-derived');

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep { /\.json$/ } readdir $dh;
closedir $dh;

for my $file (@fixture_files) {
  my $path = File::Spec->catfile($fixtures_dir, $file);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;

  my $fixture = decode_json($json);
  my $desc = $fixture->{description};
  my $input = $fixture->{input};
  my $expected = $fixture->{expected};

  subtest "$file - $desc" => sub {
    my $result = $adapter->derive_channel_presence(%{$input});

    is $result->{valid}, $expected->{overnet_valid},
      "valid = $expected->{overnet_valid}";

    if ($expected->{overnet_valid}) {
      my $got_event = { %{$result->{event}} };
      my $expected_event = { %{$expected->{event}} };

      my $got_content = delete $got_event->{content};
      my $expected_content = delete $expected_event->{content};

      is_deeply $got_event, $expected_event, 'derived event envelope matches fixture';
      is_deeply decode_json($got_content), decode_json($expected_content),
        'derived event content matches fixture semantically';
    } else {
      is $result->{reason}, $expected->{reason}, 'reason matches fixture';
    }
  };
}

done_testing;
