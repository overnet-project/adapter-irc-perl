use strict;
use warnings;
use Test::More;
use Config;
use FindBin;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});

use Net::Nostr::Group;
use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;

sub _authority_config {
  return {
    authority_profile => 'nip29',
    group_host        => 'groups.example.test',
    channel_groups    => {
      '#overnet' => 'overnet',
    },
  };
}

subtest 'authoritative KICK maps to a NIP-29 remove-user event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'KICK',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    target_nick    => 'bob',
    target_pubkey  => 'b' x 64,
    text           => 'rule violation',
    created_at     => 1_744_301_000,
  );

  ok $result->{valid}, 'authoritative KICK is accepted';
  is $result->{event}{kind}, 9001, 'authoritative KICK emits kind 9001';
  is $result->{event}{pubkey}, 'a' x 64, 'authoritative KICK uses the actor pubkey';
  is $result->{event}{content}, 'rule violation', 'authoritative KICK carries the reason in content';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      [ 'p', 'b' x 64 ],
    ],
    'authoritative KICK targets the bound NIP-29 group member',
  );
  like $result->{event}{id}, qr/\A[0-9a-f]{64}\z/, 'authoritative KICK has a deterministic unsigned event id';
  is $result->{event}{sig}, undef, 'authoritative KICK remains unsigned';
};

subtest 'authoritative MODE +o maps to a NIP-29 put-user event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+o',
    mode_args      => ['bob'],
    target_pubkey  => 'b' x 64,
    current_roles  => ['irc.voice'],
    created_at     => 1_744_301_001,
  );

  ok $result->{valid}, 'authoritative MODE +o is accepted';
  is $result->{event}{kind}, 9000, 'authoritative MODE +o emits kind 9000';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      [ 'p', 'b' x 64, 'irc.operator', 'irc.voice' ],
    ],
    'authoritative MODE +o updates roles through the NIP-29 member tag',
  );
  is $result->{event}{content}, '', 'authoritative MODE +o uses empty content when no reason is supplied';
};

subtest 'authoritative MODE +m maps to a NIP-29 metadata edit with IRC profile mode tags' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+m',
    group_metadata => {
      closed => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative MODE +m is accepted';
  is $result->{event}{kind}, 9002, 'authoritative MODE +m emits kind 9002';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'mode', 'moderated' ],
    ],
    'authoritative MODE +m preserves existing metadata flags and adds the moderated mode tag',
  );
};

subtest 'derive authoritative channel state reconstructs IRC-facing state from NIP-29 events' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'mode', 'moderated' ];

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_011,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_012,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_013,
    roles      => [
      { name => 'irc.operator' },
      { name => 'irc.voice' },
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network      => 'irc.example.test',
      target       => '#overnet',
      authoritative_events => [
        $metadata,
        $admins,
        $members,
        $roles,
      ],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds';
  is_deeply(
    $result->{state}[0],
    {
      operation         => 'authoritative_channel_state',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      channel_modes     => '+imn',
      supported_roles   => [ 'irc.operator', 'irc.voice' ],
      members           => [
        {
          pubkey               => 'a' x 64,
          roles                => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey               => 'b' x 64,
          roles                => [],
          presentational_prefix => '',
        },
      ],
    },
    'authoritative state derivation returns IRC-facing NIP-29 channel state',
  );
};

done_testing;
