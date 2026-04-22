use strict;
use warnings;
use Test::More;

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

subtest 'authoritative DELETE maps to a NIP-29 metadata edit with the tombstone status tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'DELETE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
      ban_masks        => ['*!*@evil.example'],
      topic            => 'Authoritative topic',
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative DELETE is accepted';
  is $result->{event}{kind}, 9002, 'authoritative DELETE emits kind 9002';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'mode', 'moderated' ],
      [ 'mode', 'topic-restricted' ],
      [ 'ban', '*!*@evil.example' ],
      [ 'topic', 'Authoritative topic' ],
      [ 'status', 'tombstoned' ],
    ],
    'authoritative DELETE preserves existing metadata and appends the tombstone status tag',
  );
};

subtest 'authoritative UNDELETE maps to a NIP-29 metadata edit that removes the tombstone status tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'UNDELETE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
      ban_masks        => ['*!*@evil.example'],
      topic            => 'Authoritative topic',
      tombstoned       => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative UNDELETE is accepted';
  is $result->{event}{kind}, 9002, 'authoritative UNDELETE emits kind 9002';
  is_deeply(
    $result->{event}{tags},
    [
      [ 'h', 'overnet' ],
      ['closed'],
      [ 'mode', 'moderated' ],
      [ 'mode', 'topic-restricted' ],
      [ 'ban', '*!*@evil.example' ],
      [ 'topic', 'Authoritative topic' ],
    ],
    'authoritative UNDELETE preserves retained metadata and omits the tombstone status tag',
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

subtest 'derive authoritative channel state does not treat 39002 membership snapshots as exhaustive by default' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;

  my $initial_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_021,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $partial_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_022,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $metadata,
        $initial_members,
        $partial_members,
      ],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for partial 39002 snapshots';
  is_deeply(
    $result->{state}[0]{members},
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
    'later partial 39002 snapshots do not silently delete earlier derived members',
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
      pending_join_requests => [],
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

subtest 'authoritative_join_admission allows an authenticated first join to create an absent hosted channel' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#fresh',
  );

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _dynamic_authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#fresh',
      authoritative_events => [],
      actor_pubkey         => 'a' x 64,
      actor_mask           => 'alice!alice@127.0.0.1',
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for an absent hosted channel';
  is_deeply(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#fresh',
      group_host        => 'groups.example.test',
      group_id          => $group_id,
      group_ref         => "groups.example.test'$group_id",
      allowed           => JSON::PP::true,
      member            => JSON::PP::false,
      present           => JSON::PP::false,
      create_channel    => JSON::PP::true,
      auth_required     => JSON::PP::false,
      reason            => '',
    },
    'authenticated first join may create an absent hosted authoritative channel',
  );
};

subtest 'authoritative_join_admission reports auth_required for an absent hosted channel without an actor binding' => sub {
  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _dynamic_authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#fresh',
      authoritative_events => [],
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds without an actor binding';
  is_deeply(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#fresh',
      group_host        => 'groups.example.test',
      group_id          => Overnet::Authority::HostedChannel::authoritative_group_id(
        network => 'irc.example.test',
        channel => '#fresh',
      ),
      group_ref         => "groups.example.test'" . Overnet::Authority::HostedChannel::authoritative_group_id(
        network => 'irc.example.test',
        channel => '#fresh',
      ),
      allowed           => JSON::PP::false,
      member            => JSON::PP::false,
      present           => JSON::PP::false,
      create_channel    => JSON::PP::false,
      auth_required     => JSON::PP::true,
      reason            => 'auth_required',
    },
    'absent hosted channels require authenticated actor binding before creation',
  );
};

subtest 'authoritative_join_admission returns invite-mediated admission for a closed channel' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    closed     => 1,
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

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        $metadata,
        $members,
        $invite,
      ],
      actor_pubkey => 'b' x 64,
      actor_mask   => 'bob!bob@127.0.0.1',
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for a closed invited channel';
  is_deeply(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::true,
      member            => JSON::PP::false,
      present           => JSON::PP::false,
      create_channel    => JSON::PP::false,
      auth_required     => JSON::PP::false,
      invite_code       => 'invite-bob',
      reason            => '',
    },
    'closed authoritative channels surface invite-mediated join admission symbolically',
  );
};

subtest 'authoritative_join_admission returns symbolic banned and deleted denials' => sub {
  my $banned_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_034,
    closed     => 1,
  )->to_hash;
  push @{$banned_metadata->{tags}}, [ 'ban', 'bob!bob@127.0.0.1' ];

  my $banned = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $banned_metadata ],
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
    },
  );

  ok $banned->{valid}, 'join admission derivation succeeds for a banned actor';
  is_deeply(
    $banned->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::false,
      member            => JSON::PP::false,
      present           => JSON::PP::false,
      create_channel    => JSON::PP::false,
      auth_required     => JSON::PP::false,
      reason            => '+b',
    },
    'banned joins are denied with a symbolic +b reason',
  );

  my $deleted_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_035,
    closed     => 1,
  )->to_hash;
  push @{$deleted_metadata->{tags}}, [ 'status', 'tombstoned' ];

  my $deleted = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $deleted_metadata ],
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
    },
  );

  ok $deleted->{valid}, 'join admission derivation succeeds for a tombstoned channel';
  is_deeply(
    $deleted->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::false,
      member            => JSON::PP::false,
      present           => JSON::PP::false,
      create_channel    => JSON::PP::false,
      auth_required     => JSON::PP::false,
      deleted           => JSON::PP::true,
      reason            => 'deleted',
    },
    'tombstoned channels are denied with a symbolic deleted reason',
  );
};

subtest 'authoritative_speak_permission enforces moderated channel voice and operator exemptions' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'mode', 'moderated' ];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_041,
    members    => [
      'a' x 64,
      'b' x 64,
      'c' x 64,
    ],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_042,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $voice = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_043,
    target     => 'b' x 64,
    roles      => ['irc.voice'],
  )->to_hash;

  my $voiced = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops, $voice ],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $voiced->{valid}, 'speak permission derivation succeeds for voiced members';
  is_deeply(
    $voiced->{permission}[0],
    {
      operation         => 'authoritative_speak_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::true,
      roles             => ['irc.voice'],
      presentational_prefix => '+',
      reason            => '',
    },
    'voiced members may speak in moderated authoritative channels',
  );

  my $unvoiced = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops, $voice ],
      actor_pubkey         => 'c' x 64,
    },
  );

  ok $unvoiced->{valid}, 'speak permission derivation succeeds for unvoiced members';
  is_deeply(
    $unvoiced->{permission}[0],
    {
      operation         => 'authoritative_speak_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::false,
      roles             => [],
      presentational_prefix => '',
      reason            => '+m',
    },
    'unvoiced non-operators are denied speak permission in moderated authoritative channels',
  );
};

subtest 'authoritative_topic_permission enforces topic-restricted operator rules' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_044,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'mode', 'topic-restricted' ];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_045,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_046,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $operator = $adapter->derive(
    operation      => 'authoritative_topic_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops ],
      actor_pubkey         => 'a' x 64,
    },
  );

  ok $operator->{valid}, 'topic permission derivation succeeds for operators';
  is_deeply(
    $operator->{permission}[0],
    {
      operation         => 'authoritative_topic_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::true,
      reason            => '',
    },
    'operators may change topic on topic-restricted authoritative channels',
  );

  my $member = $adapter->derive(
    operation      => 'authoritative_topic_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops ],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $member->{valid}, 'topic permission derivation succeeds for non-operators';
  is_deeply(
    $member->{permission}[0],
    {
      operation         => 'authoritative_topic_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::false,
      reason            => '+t',
    },
    'non-operators are denied topic permission on topic-restricted authoritative channels',
  );
};

subtest 'authoritative_mode_write_permission resolves operator mode and ban context' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_047,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'closed' ];
  push @{$metadata->{tags}}, [ 'mode', 'moderated' ];
  push @{$metadata->{tags}}, [ 'mode', 'topic-restricted' ];
  push @{$metadata->{tags}}, [ 'ban', '*!*@banned.example' ];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_048,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_049,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $voice = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_050,
    target     => 'b' x 64,
    roles      => ['irc.voice'],
  )->to_hash;

  my $grant_voice = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops, $voice ],
      actor_pubkey         => 'a' x 64,
      mode                 => '+v',
      mode_args            => [ 'b' x 64 ],
    },
  );

  ok $grant_voice->{valid}, 'mode permission derivation succeeds for operators';
  is_deeply(
    $grant_voice->{permission}[0],
    {
      operation         => 'authoritative_mode_write_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::true,
      mode              => '+v',
      target_pubkey     => 'b' x 64,
      current_roles     => ['irc.voice'],
      reason            => '',
    },
    'operator mode writes expose the current target pubkey and roles',
  );

  my $set_ban = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops, $voice ],
      actor_pubkey         => 'a' x 64,
      mode                 => '+b',
      mode_args            => [ '*!*@new.example' ],
    },
  );

  ok $set_ban->{valid}, 'ban mode permission derivation succeeds for operators';
  is_deeply(
    $set_ban->{permission}[0],
    {
      operation         => 'authoritative_mode_write_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::true,
      mode              => '+b',
      normalized_ban_mask => '*!*@new.example',
      group_metadata    => {
        closed           => 1,
        moderated        => 1,
        topic_restricted => 1,
        private          => 0,
        hidden           => 0,
        restricted       => 0,
        ban_masks        => [ '*!*@banned.example' ],
        tombstoned       => 0,
      },
      reason            => '',
    },
    'ban mode writes expose current authoritative metadata for subsequent mapping',
  );

  my $non_operator = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $ops, $voice ],
      actor_pubkey         => 'b' x 64,
      mode                 => '+m',
      mode_args            => [],
    },
  );

  ok $non_operator->{valid}, 'mode permission derivation still succeeds for non-operators';
  is_deeply(
    $non_operator->{permission}[0],
    {
      operation         => 'authoritative_mode_write_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      allowed           => JSON::PP::false,
      mode              => '+m',
      reason            => 'not_operator',
    },
    'non-operators are denied authoritative mode writes with a symbolic reason',
  );
};

subtest 'authoritative_channel_action_permission resolves kick, delete, and undelete rules' => sub {
  my $live_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_051,
  )->to_hash;

  my $live_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_052,
    members    => [
      'a' x 64,
      'b' x 64,
    ],
  )->to_hash;

  my $live_ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_053,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $kick = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $live_metadata, $live_members, $live_ops ],
      actor_pubkey         => 'a' x 64,
      action               => 'kick',
      target_pubkey        => 'b' x 64,
    },
  );

  ok $kick->{valid}, 'action permission derivation succeeds for kick';
  is_deeply(
    $kick->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      action            => 'kick',
      allowed           => JSON::PP::true,
      target_pubkey     => 'b' x 64,
      reason            => '',
    },
    'kick permission returns the resolved target context for operators',
  );

  my $delete = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $live_metadata, $live_members, $live_ops ],
      actor_pubkey         => 'b' x 64,
      action               => 'delete',
    },
  );

  ok $delete->{valid}, 'action permission derivation still succeeds for rejected delete';
  is_deeply(
    $delete->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      action            => 'delete',
      allowed           => JSON::PP::false,
      reason            => 'not_operator',
    },
    'non-operators are denied authoritative channel actions with a symbolic reason',
  );

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_054,
  )->to_hash;
  push @{$tombstoned->{tags}}, [ 'status', 'tombstoned' ];
  push @{$tombstoned->{tags}}, [ 'topic', 'retained topic' ];

  my $undelete = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $live_members, $live_ops, $tombstoned ],
      actor_pubkey         => 'a' x 64,
      action               => 'undelete',
    },
  );

  ok $undelete->{valid}, 'action permission derivation succeeds for undelete';
  is_deeply(
    $undelete->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      action            => 'undelete',
      allowed           => JSON::PP::true,
      group_metadata    => {
        closed           => 0,
        moderated        => 0,
        topic_restricted => 0,
        private          => 0,
        hidden           => 0,
        restricted       => 0,
        ban_masks        => [],
        tombstoned       => 1,
        topic            => 'retained topic',
      },
      reason            => '',
    },
    'retained operators may undelete and receive the retained metadata context',
  );
};

subtest 'authoritative_ban_list_view returns stable normalized authoritative ban masks' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_055,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'ban', '*!*@z.example' ];
  push @{$metadata->{tags}}, [ 'ban', '*!*@a.example' ];
  push @{$metadata->{tags}}, [ 'ban', '*!*@a.example' ];

  my $result = $adapter->derive(
    operation      => 'authoritative_ban_list_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata ],
    },
  );

  ok $result->{valid}, 'ban-list view derivation succeeds';
  is_deeply(
    $result->{view}[0],
    {
      operation         => 'authoritative_ban_list_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      ban_masks         => [
        '*!*@a.example',
        '*!*@z.example',
      ],
    },
    'ban-list view exposes stable normalized authoritative ban masks',
  );
};

subtest 'authoritative_list_entry_view reports list visibility and presentational state' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_056,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'topic', 'Authoritative topic' ];
  push @{$metadata->{tags}}, [ 'mode', 'moderated' ];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_057,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_058,
  )->to_hash;

  my $visible = $adapter->derive(
    operation      => 'authoritative_list_entry_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $join ],
    },
  );

  ok $visible->{valid}, 'list-entry view derivation succeeds';
  is_deeply(
    $visible->{view}[0],
    {
      operation         => 'authoritative_list_entry_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      channel           => '#overnet',
      visible_in_list   => JSON::PP::true,
      channel_modes     => '+mn',
      visible_users     => 1,
      topic             => 'Authoritative topic',
    },
    'list-entry view exposes canonical list presentation for visible hosted channels',
  );

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_059,
  )->to_hash;
  push @{$tombstoned->{tags}}, [ 'status', 'tombstoned' ];

  my $hidden = $adapter->derive(
    operation      => 'authoritative_list_entry_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [ $metadata, $members, $join, $tombstoned ],
    },
  );

  ok $hidden->{valid}, 'list-entry view derivation succeeds for tombstoned channels';
  is_deeply(
    $hidden->{view}[0],
    {
      operation         => 'authoritative_list_entry_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => "groups.example.test'overnet",
      channel           => '#overnet',
      visible_in_list   => JSON::PP::false,
      reason            => 'deleted',
    },
    'tombstoned hosted channels are suppressed from authoritative LIST output',
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

subtest 'authoritative_channel_view applies same-second invite before join regardless of authority tag ordering' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_043,
    closed     => 1,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_044,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_045,
  )->to_hash;
  push @{$invite_bob->{tags}},
    [ 'p', 'b' x 64 ],
    [ 'overnet_actor', 'a' x 64 ],
    [ 'overnet_authority', 'f' x 64 ],
    [ 'overnet_sequence', 1 ];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_045,
  )->to_hash;
  push @{$join_bob->{tags}},
    [ 'overnet_actor', 'b' x 64 ],
    [ 'overnet_authority', '1' x 64 ],
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

  ok $result->{valid}, 'derivation succeeds when same-second invite and join use conflicting authority sort order';
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
    'invite admission still applies before the same-second join even when authority tags sort the other way',
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
    'same-second invite-plus-join still yields present membership after the semantic invite phase',
  );
};

subtest 'authoritative_channel_view applies same-second removal after join regardless of authority tag ordering' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_046,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_047,
    members    => [
      'a' x 64,
    ],
  )->to_hash;

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_048,
  )->to_hash;
  push @{$join_bob->{tags}},
    [ 'overnet_actor', 'b' x 64 ],
    [ 'overnet_authority', 'f' x 64 ],
    [ 'overnet_sequence', 1 ];

  my $remove_bob = Net::Nostr::Group->remove_user(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_301_048,
  )->to_hash;
  push @{$remove_bob->{tags}},
    [ 'overnet_actor', 'a' x 64 ],
    [ 'overnet_authority', '1' x 64 ],
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
        $remove_bob,
      ],
    },
  );

  ok $result->{valid}, 'derivation succeeds when same-second join and removal use conflicting authority sort order';
  is_deeply(
    $result->{view}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'same-second removal still applies after the join and removes the member even when authority tags sort first',
  );
  is_deeply(
    $result->{view}[0]{present_members},
    [],
    'same-second removal clears present membership after the semantic removal phase',
  );
};

subtest 'derive authoritative channel view treats a tombstoned hosted channel as deleted and non-admissible' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'status', 'tombstoned' ];

  my $operator = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_011,
    roles      => ['irc.operator'],
  )->to_hash;

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_012,
  )->to_hash;
  push @{$join->{tags}}, [ 'overnet_actor', 'a' x 64 ];

  my $result = $adapter->derive(
    operation          => 'authoritative_channel_view',
    session_config     => _authority_config(),
    input              => {
      network            => 'irc.example.test',
      target             => '#overnet',
      actor_pubkey       => 'a' x 64,
      authoritative_events => [
        $metadata,
        $operator,
        $join,
      ],
    },
  );

  ok $result->{valid}, 'tombstoned authoritative channel view derives successfully';
  ok $result->{view}[0]{tombstoned}, 'the derived authoritative channel view is marked tombstoned';
  is_deeply $result->{view}[0]{members}, [],
    'tombstoned authoritative channels do not expose current members';
  is_deeply $result->{view}[0]{present_members}, [],
    'tombstoned authoritative channels do not expose present members';
  ok $result->{view}[0]{admission}{deleted}, 'tombstoned authoritative channels report a deleted admission result';
  ok !$result->{view}[0]{admission}{allowed}, 'tombstoned authoritative channels reject JOIN admission';
  is $result->{view}[0]{admission}{reason}, 'deleted',
    'tombstoned authoritative channels expose a deleted admission reason';
};

subtest 'derive authoritative channel view restores retained metadata and durable membership after UNDELETE while clearing presence and invites' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, [ 'topic', 'Retained topic' ];

  my $operator = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_011,
    roles      => ['irc.operator'],
  )->to_hash;

  my $member = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_301_012,
    roles      => [],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-carol',
    created_at => 1_744_301_013,
  )->to_hash;
  push @{$invite->{tags}}, [ 'p', 'c' x 64 ];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_014,
  )->to_hash;
  push @{$join->{tags}}, [ 'overnet_actor', 'a' x 64 ];

  my $tombstone = Net::Nostr::Group->edit_metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_015,
    closed     => 1,
  )->to_hash;
  push @{$tombstone->{tags}}, [ 'topic', 'Retained topic' ];
  push @{$tombstone->{tags}}, [ 'status', 'tombstoned' ];

  my $undelete = Net::Nostr::Group->edit_metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_016,
    closed     => 1,
  )->to_hash;
  push @{$undelete->{tags}}, [ 'topic', 'Retained topic' ];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network            => 'irc.example.test',
      target             => '#overnet',
      actor_pubkey       => 'b' x 64,
      authoritative_events => [
        $metadata,
        $operator,
        $member,
        $invite,
        $join,
        $tombstone,
        $undelete,
      ],
    },
  );

  ok $result->{valid}, 'reactivated authoritative channel view derives successfully';
  ok !$result->{view}[0]{tombstoned}, 'the reactivated authoritative channel view is no longer marked tombstoned';
  is $result->{view}[0]{channel_modes}, '+in',
    'reactivated authoritative channels retain the pre-delete closed mode';
  is $result->{view}[0]{topic}, 'Retained topic',
    'reactivated authoritative channels retain the prior topic metadata';
  is_deeply $result->{view}[0]{members}, [
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
  ], 'reactivated authoritative channels restore retained durable membership';
  is_deeply $result->{view}[0]{present_members}, [],
    'reactivated authoritative channels clear pre-delete present-member state';
  is_deeply $result->{view}[0]{pending_invites}, [],
    'reactivated authoritative channels clear pre-delete pending invites';
  ok $result->{view}[0]{admission}{member}, 'retained members remain authoritative members after UNDELETE';
  ok $result->{view}[0]{admission}{allowed}, 'retained members may JOIN again after UNDELETE';
  is $result->{view}[0]{admission}{reason}, '',
    'reactivated authoritative channels do not report a join denial reason for retained members';
};

done_testing;
