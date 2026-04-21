use strict;
use warnings;
use Test::More;
use JSON::PP;
use Config;
use FindBin;
use File::Basename;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-core-perl', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});

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

subtest 'generic derive dispatches channel_presence' => sub {
  my $result = $adapter->derive(
    operation => 'channel_presence',
    input     => {
      network    => 'irc.libera.chat',
      target     => '#overnet',
      created_at => 1744300900,
      events     => [
        {
          command    => 'JOIN',
          network    => 'irc.libera.chat',
          target     => '#overnet',
          nick       => 'alice',
          created_at => 1744300870,
        },
      ],
    },
  );

  ok $result->{valid}, 'generic derive returns a valid result';
  is $result->{event}{kind}, 37800, 'generic derive returns derived state event';
};

subtest 'generic derive rejects unsupported operations' => sub {
  my $result = $adapter->derive(
    operation => 'unknown_operation',
    input     => {},
  );

  ok !$result->{valid}, 'unsupported derive operation is rejected';
  is $result->{reason}, 'Unsupported derive operation: unknown_operation', 'unsupported operation reason is reported';
};

subtest 'adapter declares secure secret slots for runtime session opens' => sub {
  is_deeply(
    $adapter->supported_secret_slots,
    [ 'server_password', 'nickserv_password', 'sasl_password' ],
    'IRC adapter declares the supported runtime secret slots',
  );
};

subtest 'open_session accepts declared secret slots without exposing plaintext back out' => sub {
  my $result = $adapter->open_session(
    adapter_session_id => 'adapter-1',
    session_config     => {
      network => 'irc.libera.chat',
      nick    => 'overnet-bot',
    },
    secret_values      => {
      sasl_password => 'super-secret',
    },
  );

  ok $result->{accepted}, 'open_session accepts valid declared secret slots';

  like(
    do {
      my $error;
      eval {
        $adapter->open_session(
          adapter_session_id => 'adapter-2',
          session_config     => {},
          secret_values      => {
            unsupported_slot => 'secret',
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/Unsupported IRC secret slot: unsupported_slot/,
    'open_session rejects unsupported secret slots',
  );
};

done_testing;
