use strict;
use warnings;
use Test::More;
use Config;
use FindBin;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5', $Config{version});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'local', 'lib', 'perl5', $Config{version}, $Config{archname});
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-code', 'lib');

use Net::Nostr::Group;
use Overnet::Authority::HostedChannel ();
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

sub _dynamic_authority_config {
  return {
    authority_profile => 'nip29',
    group_host        => 'groups.example.test',
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

subtest 'authoritative MODE +b and -b map to NIP-29 metadata edits carrying the IRC ban list' => sub {
  my $add_result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+b',
    ban_mask       => 'bob!bob@127.0.0.1',
    group_metadata => {
      closed    => 1,
      ban_masks => ['*!*@evil.example'],
    },
    created_at => 1_744_301_002,
  );

  ok $add_result->{valid}, 'authoritative MODE +b is accepted';
  is $add_result->{event}{kind}, 9002, 'authoritative MODE +b emits kind 9002';
  is_deeply(
    $add_result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'ban', '*!*@evil.example' ],
      [ 'ban', 'bob!bob@127.0.0.1' ],
    ],
    'authoritative MODE +b preserves existing bans and appends the new IRC ban mask',
  );

  my $remove_result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '-b',
    ban_mask       => 'bob!bob@127.0.0.1',
    group_metadata => {
      closed    => 1,
      ban_masks => [ 'bob!bob@127.0.0.1', '*!*@evil.example' ],
    },
    created_at => 1_744_301_003,
  );

  ok $remove_result->{valid}, 'authoritative MODE -b is accepted';
  is $remove_result->{event}{kind}, 9002, 'authoritative MODE -b emits kind 9002';
  is_deeply(
    $remove_result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'ban', '*!*@evil.example' ],
    ],
    'authoritative MODE -b removes only the targeted IRC ban mask',
  );
};

subtest 'authoritative TOPIC maps to a NIP-29 metadata edit with the IRC topic tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'TOPIC',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    text           => 'Authoritative topic',
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative TOPIC is accepted';
  is $result->{event}{kind}, 9002, 'authoritative TOPIC emits kind 9002';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'mode', 'moderated' ],
      [ 'mode', 'topic-restricted' ],
      [ 'topic', 'Authoritative topic' ],
    ],
    'authoritative TOPIC preserves existing metadata flags and carries the IRC topic tag',
  );
};

subtest 'authoritative INVITE maps to a NIP-29 create-invite event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'INVITE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    target_nick    => 'bob',
    target_pubkey  => 'b' x 64,
    invite_code    => 'invite-bob',
    created_at     => 1_744_301_003,
  );

  ok $result->{valid}, 'authoritative INVITE is accepted';
  is $result->{event}{kind}, 9009, 'authoritative INVITE emits kind 9009';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      [ 'code', 'invite-bob' ],
      [ 'p', 'b' x 64 ],
    ],
    'authoritative INVITE targets the bound NIP-29 group with an invite code and invitee pubkey',
  );
  is $result->{event}{content}, '', 'authoritative INVITE uses empty content by default';
};

subtest 'authoritative JOIN can bootstrap a newly created hosted channel without static channel_groups' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#Fresh',
  );
  my $result = $adapter->map_input(
    session_config     => _dynamic_authority_config(),
    command            => 'JOIN',
    network            => 'irc.example.test',
    target             => '#Fresh',
    nick               => 'alice',
    actor_pubkey       => 'a' x 64,
    signing_pubkey     => 'd' x 64,
    authority_event_id => 'e' x 64,
    authority_sequence => 11,
    create_channel     => 1,
    group_metadata     => {
      name => '#Fresh',
    },
    created_at => 1_744_301_003,
  );

  ok $result->{valid}, 'authoritative bootstrap JOIN is accepted';
  ok ref($result->{events}) eq 'ARRAY', 'authoritative bootstrap JOIN emits multiple event drafts';
  is scalar(@{$result->{events}}), 3, 'authoritative bootstrap JOIN emits metadata, operator bootstrap, and join drafts';
  is_deeply(
    [ map { $_->{kind} } @{$result->{events}} ],
    [ 39000, 9000, 9021 ],
    'authoritative bootstrap JOIN emits the expected NIP-29 event kinds',
  );
  is_deeply(
    $result->{events}[0]{tags},
    [
      [ 'd', $group_id ],
      [ 'name', '#Fresh' ],
      [ 'overnet_actor', 'a' x 64 ],
      [ 'overnet_authority', 'e' x 64 ],
      [ 'overnet_sequence', 11 ],
    ],
    'authoritative bootstrap metadata uses the deterministic binding and delegated authority tags',
  );
  is_deeply(
    $result->{events}[1]{tags},
    [
      [ 'h', $group_id ],
      [ 'p', 'a' x 64, 'irc.operator' ],
      [ 'overnet_actor', 'a' x 64 ],
      [ 'overnet_authority', 'e' x 64 ],
      [ 'overnet_sequence', 11 ],
    ],
    'authoritative bootstrap role event seeds the creator as irc.operator',
  );
  is_deeply(
    $result->{events}[2]{tags},
    [
      [ 'h', $group_id ],
      [ 'overnet_actor', 'a' x 64 ],
      [ 'overnet_authority', 'e' x 64 ],
      [ 'overnet_sequence', 11 ],
    ],
    'authoritative bootstrap join uses the deterministic binding and delegated actor tags',
  );
};

subtest 'authoritative JOIN can target a delegated signer while preserving the effective actor' => sub {
  my $result = $adapter->map_input(
    session_config      => _authority_config(),
    command             => 'JOIN',
    network             => 'irc.example.test',
    target              => '#overnet',
    nick                => 'bob',
    actor_pubkey        => 'b' x 64,
    signing_pubkey      => 'd' x 64,
    authority_event_id  => 'e' x 64,
    authority_sequence  => 7,
    invite_code         => 'invite-bob',
    created_at          => 1_744_301_004,
  );

  ok $result->{valid}, 'delegated authoritative JOIN is accepted';
  is $result->{event}{kind}, 9021, 'delegated authoritative JOIN emits kind 9021';
  is $result->{event}{pubkey}, 'd' x 64, 'delegated authoritative JOIN uses the delegated signer pubkey';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      [ 'code', 'invite-bob' ],
      [ 'overnet_actor', 'b' x 64 ],
      [ 'overnet_authority', 'e' x 64 ],
      [ 'overnet_sequence', 7 ],
    ],
    'delegated authoritative JOIN preserves the effective actor, authority grant reference, and session sequence',
  );
};

subtest 'authoritative PART maps to a NIP-29 leave-request event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'PART',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'bob',
    actor_pubkey   => 'b' x 64,
    text           => 'later',
    created_at     => 1_744_301_005,
  );

  ok $result->{valid}, 'authoritative PART is accepted';
  is $result->{event}{kind}, 9022, 'authoritative PART emits kind 9022';
  is $result->{event}{pubkey}, 'b' x 64, 'authoritative PART uses the actor pubkey';
  is $result->{event}{content}, 'later', 'authoritative PART carries the part reason in content';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
    ],
    'authoritative PART targets the bound NIP-29 group without a member p tag',
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

subtest 'derive authoritative channel state accepts a matching invite code plus join request as local membership' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_021,
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
    created_at => 1_744_301_022,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_023,
    roles      => [
      { name => 'irc.operator' },
      { name => 'irc.voice' },
    ],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_024,
  )->to_hash;
  push @{$invite->{tags}}, [ 'p', 'b' x 64 ];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_025,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $metadata,
        $admins,
        $members,
        $roles,
        $invite,
        $join,
      ],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for invite-mediated admission';
  is $result->{state}[0]{channel_modes}, '+in', 'closed authoritative channel keeps +i and implicit +n';
  is_deeply(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'matching invite plus join request produces derived local membership for the invited pubkey',
  );
};

subtest 'derive authoritative channel state removes local membership after a leave request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_026,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_027,
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
    created_at => 1_744_301_028,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_029,
  )->to_hash;
  push @{$invite->{tags}}, [ 'p', 'b' x 64 ];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_030,
  )->to_hash;

  my $leave = Net::Nostr::Group->leave_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    reason     => 'later',
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $metadata,
        $admins,
        $members,
        $invite,
        $join,
        $leave,
      ],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for leave requests';
  is_deeply(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
    ],
    'leave requests remove the local member from derived authoritative membership',
  );
};

subtest 'derive authoritative channel state uses overnet_actor for delegated join requests' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_030,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
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
    created_at => 1_744_301_032,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_033,
  )->to_hash;
  push @{$invite->{tags}}, [ 'p', 'b' x 64 ];

  my $delegated_join = Net::Nostr::Group->join_request(
    pubkey     => 'd' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_034,
  )->to_hash;
  push @{$delegated_join->{tags}},
    [ 'overnet_actor', 'b' x 64 ],
    [ 'overnet_authority', 'e' x 64 ];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $metadata,
        $admins,
        $members,
        $invite,
        $delegated_join,
      ],
    },
  );

  ok $result->{valid}, 'delegated authoritative state derivation succeeds';
  is_deeply(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'delegated join requests admit the effective actor pubkey rather than the delegated signer',
  );
};

subtest 'authoritative_channel_view sorts authoritative events and exposes admission, invites, and presence' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'mode', 'moderated' ], [ 'mode', 'topic-restricted' ];
  push @{$metadata->{tags}}, [ 'topic', 'Current authoritative topic' ], [ 'overnet_actor', 'a' x 64 ];

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_024,
    roles      => [
      { name => 'irc.operator' },
      { name => 'irc.voice' },
    ],
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_019,
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
    created_at => 1_744_301_018,
    members    => [
      'a' x 64,
      'c' x 64,
    ],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_021,
  )->to_hash;
  push @{$invite_bob->{tags}},
    [ 'p', 'b' x 64 ],
    [ 'overnet_actor', 'a' x 64 ],
    [ 'overnet_authority', '1' x 64 ],
    [ 'overnet_sequence', 1 ];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => 'd' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_021,
  )->to_hash;
  push @{$join_bob->{tags}},
    [ 'overnet_actor', 'b' x 64 ],
    [ 'overnet_authority', '1' x 64 ],
    [ 'overnet_sequence', 2 ];

  my $invite_carol = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-carol',
    created_at => 1_744_301_025,
  )->to_hash;
  push @{$invite_carol->{tags}}, [ 'p', 'e' x 64 ];

  my $join_alice = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_026,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'e' x 64,
      authoritative_events => [
        $join_bob,
        $roles,
        $metadata,
        $invite_carol,
        $join_alice,
        $members,
        $invite_bob,
        $admins,
      ],
    },
  );

  ok $result->{valid}, 'authoritative channel view derivation succeeds';
  is_deeply(
    $result->{view}[0],
    {
      operation         => 'authoritative_channel_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      channel_modes     => '+imnt',
      topic             => 'Current authoritative topic',
      topic_actor_pubkey => 'a' x 64,
      supported_roles   => [ 'irc.operator', 'irc.voice' ],
      members           => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
        {
          pubkey                => 'c' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
      present_members   => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
      pending_invites   => [
        {
          code          => 'invite-carol',
          target_pubkey => 'e' x 64,
        },
      ],
      admission         => {
        allowed     => JSON::PP::true,
        member      => JSON::PP::false,
        invite_code => 'invite-carol',
        reason      => '',
      },
    },
    'authoritative channel view exposes sorted state, pending invites, presence, and actor-specific admission',
  );
};

subtest 'authoritative_channel_view exposes ban masks and rejects banned joins by IRC mask' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_027,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'ban', 'bob!bob@127.0.0.1' ];

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_028,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'Bob!bob@127.0.0.1',
      authoritative_events => [
        $admins,
        $metadata,
      ],
    },
  );

  ok $result->{valid}, 'authoritative channel view derivation succeeds for ban enforcement';
  is_deeply(
    $result->{view}[0]{ban_masks},
    ['bob!bob@127.0.0.1'],
    'authoritative channel view exposes the current authoritative IRC ban list',
  );
  is_deeply(
    $result->{view}[0]{admission},
    {
      allowed => JSON::PP::false,
      member  => JSON::PP::false,
      reason  => '+b',
    },
    'authoritative admission rejects a join whose IRC mask matches the ban list',
  );
};

subtest 'authoritative_channel_state remains a projection of authoritative_channel_view' => sub {
  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_030,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $members,
        $admins,
      ],
    },
  );

  ok $result->{valid}, 'compatibility projection succeeds';
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
      channel_modes     => '+n',
      supported_roles   => [],
      members           => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
    },
    'authoritative_channel_state still returns the legacy projection',
  );
};

subtest 'authoritative_channel_view orders same-second invite and join causally across authorities' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
    closed     => 1,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_041,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_042,
  )->to_hash;
  push @{$invite_bob->{tags}},
    [ 'p', 'b' x 64 ],
    [ 'overnet_actor', 'a' x 64 ],
    [ 'overnet_authority', '1' x 64 ],
    [ 'overnet_sequence', 5 ];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => '2' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_042,
  )->to_hash;
  push @{$join_bob->{tags}},
    [ 'overnet_actor', 'b' x 64 ],
    [ 'overnet_authority', '2' x 64 ],
    [ 'overnet_sequence', 1 ];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $join_bob,
        $metadata,
        $members,
        $invite_bob,
      ],
    },
  );

  ok $result->{valid}, 'derivation succeeds when same-second invite and join come from different authorities';
  is_deeply(
    $result->{view}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'semantic ordering still applies the invite before the join across authorities',
  );
  is_deeply(
    $result->{view}[0]{present_members},
    [
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'same-second cross-authority join produces presence after the invite is applied',
  );
};

done_testing;
