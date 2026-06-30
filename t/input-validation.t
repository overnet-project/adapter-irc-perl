use strictures 2;

use Test2::V0;

use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;

subtest 'standard mapping rejects non-numeric created_at' => sub {
  my $result = $adapter->map_input(
    command    => 'PRIVMSG',
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hello',
    created_at => 'not-a-timestamp',
  );

  ok !$result->{valid}, 'mapping is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';
};

subtest 'authoritative mapping rejects non-numeric created_at' => sub {
  my $result = $adapter->map_input(
    session_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      channel_groups    => {
        '#overnet' => 'overnet',
      },
    },
    command       => 'KICK',
    network       => 'irc.example.test',
    target        => '#overnet',
    nick          => 'alice',
    actor_pubkey  => 'a' x 64,
    target_nick   => 'bob',
    target_pubkey => 'b' x 64,
    created_at    => 'not-a-timestamp',
  );

  ok !$result->{valid}, 'authoritative mapping is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';
};

subtest 'derived presence rejects non-numeric created_at values' => sub {
  my $result = $adapter->derive_channel_presence(
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 'not-a-timestamp',
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.example.test',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 1_744_301_000,
      },
    ],
  );

  ok !$result->{valid}, 'derived presence is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';

  $result = $adapter->derive_channel_presence(
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 1_744_301_001,
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.example.test',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 'not-a-timestamp',
      },
    ],
  );

  ok !$result->{valid}, 'derived presence event is rejected';
  is $result->{reason}, 'derived presence event created_at must be a non-negative integer',
    'reason identifies invalid event timestamp';
};

done_testing;
