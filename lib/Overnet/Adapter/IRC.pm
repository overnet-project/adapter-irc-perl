package Overnet::Adapter::IRC;

use strict;
use warnings;
use JSON::PP ();
use Net::Nostr::Event;
use Net::Nostr::Group;

our $VERSION = '0.001';
my $JSON = JSON::PP->new;

sub new {
  my ($class, %args) = @_;
  $args{overnet_version} //= '0.1.0';
  $args{session_state} ||= {};
  return bless \%args, $class;
}

sub supported_secret_slots {
  return [
    'server_password',
    'nickserv_password',
    'sasl_password',
  ];
}

sub open_session {
  my ($self, %args) = @_;
  my $adapter_session_id = $args{adapter_session_id};
  my $session_config = $args{session_config} || {};
  my $secret_values = $args{secret_values} || {};
  my %supported = map { $_ => 1 } @{supported_secret_slots()};

  die "adapter_session_id is required\n"
    unless defined $adapter_session_id && length $adapter_session_id;
  die "session_config must be an object\n"
    if ref($session_config) ne 'HASH';
  die "secret_values must be an object\n"
    if ref($secret_values) ne 'HASH';

  for my $slot (sort keys %{$secret_values}) {
    die "Unsupported IRC secret slot: $slot\n"
      unless $supported{$slot};
    die "IRC secret slot $slot must be a string\n"
      if !defined($secret_values->{$slot}) || ref($secret_values->{$slot});
  }

  $self->{session_state}{$adapter_session_id} = {
    secret_slots => { map { $_ => 1 } sort keys %{$secret_values} },
  };

  return {
    accepted => JSON::PP::true,
  };
}

sub close_session {
  my ($self, %args) = @_;
  my $adapter_session_id = $args{adapter_session_id};

  die "adapter_session_id is required\n"
    unless defined $adapter_session_id && length $adapter_session_id;

  delete $self->{session_state}{$adapter_session_id};
  return 1;
}

sub map_input {
  my ($self, %args) = @_;
  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};

  my $command = $args{command};
  return _error('IRC command is required')
    unless defined $command && length $command;

  return _error("Unsupported IRC command: $command")
    unless $command eq 'PRIVMSG'
      || $command eq 'NOTICE'
      || $command eq 'TOPIC'
      || $command eq 'JOIN'
      || $command eq 'INVITE'
      || $command eq 'PART'
      || $command eq 'QUIT'
      || $command eq 'KICK'
      || $command eq 'NICK'
      || $command eq 'MODE';

  my $network = $args{network};
  return _error('IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  if ($command ne 'NICK') {
    return _error('IRC target is required')
      unless defined $target && length $target;
  }

  my $nick = $args{nick};
  return _error('Sender nick is required')
    unless defined $nick && length $nick;

  my $text = $args{text};
  my $created_at = $args{created_at};
  return _error('created_at is required')
    unless defined $created_at;

  my %irc_identity;

  if (exists $args{account}) {
    return _error('IRC account must be a non-empty string')
      unless defined $args{account} && length $args{account};
    $irc_identity{account} = $args{account};
  }

  if (exists $args{user}) {
    return _error('IRC user must be a non-empty string')
      unless defined $args{user} && length $args{user};
    $irc_identity{user} = $args{user};
  }

  if (exists $args{host}) {
    return _error('IRC host must be a non-empty string')
      unless defined $args{host} && length $args{host};
    $irc_identity{host} = $args{host};
  }

  if ($command eq 'MODE' && exists $args{mode_args}) {
    return _error('MODE mode_args must be an array of non-empty strings')
      unless ref($args{mode_args}) eq 'ARRAY'
        && !grep { !defined($_) || ref($_) || !length($_) } @{$args{mode_args}};
  }

  my $is_channel_target = defined $target && $target =~ /\A[#&]/ ? 1 : 0;
  my ($kind, $event_type, $object_type, $object_id, $origin, $body);

  if (($session_config->{authority_profile} || '') eq 'nip29'
      && ($command eq 'KICK' || $command eq 'MODE' || $command eq 'INVITE' || $command eq 'JOIN')
      && $is_channel_target) {
    return $self->_map_nip29_authoritative_input(
      %args,
      session_config => $session_config,
    );
  }

  return _error("Unsupported IRC command: $command")
    if $command eq 'INVITE';

  if ($command eq 'NICK') {
    return _error('NICK new_nick is required')
      unless defined $args{new_nick} && length $args{new_nick};

    $kind = 7800;
    $event_type = 'irc.nick';
    $object_type = 'irc.network';
    $object_id = "irc:$network";
    $origin = $network;
    $body = {
      old_nick => $nick,
      new_nick => $args{new_nick},
    };
  } elsif ($command eq 'MODE') {
    return _error('MODE target must be a channel')
      unless $is_channel_target;

    return _error('MODE mode is required')
      unless defined $args{mode} && length $args{mode};

    $kind = 7800;
    $event_type = 'irc.mode';
    $object_type = 'chat.channel';
    $object_id = "irc:$network:$target";
    $origin = "$network/$target";
    $body = {
      mode => $args{mode},
    };
    $body->{mode_args} = [ @{$args{mode_args}} ]
      if exists $args{mode_args};
  } elsif ($command eq 'TOPIC') {
    return _error('TOPIC target must be a channel')
      unless $is_channel_target;

    return _error('TOPIC text is required')
      unless defined $text;

    $kind = 37800;
    $event_type = 'chat.topic';
    $object_type = 'chat.channel';
    $object_id = "irc:$network:$target";
    $origin = "$network/$target";
    $body = {
      topic => $text,
    };
  } elsif ($command eq 'JOIN' || $command eq 'PART' || $command eq 'QUIT' || $command eq 'KICK') {
    my %event_type_for = (
      JOIN => 'chat.join',
      PART => 'chat.part',
      QUIT => 'chat.quit',
      KICK => 'chat.kick',
    );
    my %target_error_for = (
      JOIN => 'JOIN target must be a channel',
      PART => 'PART target must be a channel',
      QUIT => 'QUIT target must be a channel',
      KICK => 'KICK target must be a channel',
    );

    return _error($target_error_for{$command})
      unless $is_channel_target;

    if ($command eq 'KICK') {
      return _error('KICK target_nick is required')
        unless defined $args{target_nick} && length $args{target_nick};
    }

    $kind = 7800;
    $event_type = $event_type_for{$command};
    $object_type = 'chat.channel';
    $object_id = "irc:$network:$target";
    $origin = "$network/$target";
    $body = {};
    $body->{target_nick} = $args{target_nick}
      if $command eq 'KICK';
    $body->{reason} = $text
      if defined $text && length $text;
  } else {
    return _error('Message text is required')
      unless defined $text && length $text;

    $kind = 7800;

    if ($is_channel_target) {
      $event_type = $command eq 'PRIVMSG' ? 'chat.message' : 'chat.notice';
      $object_type = 'chat.channel';
      $object_id = "irc:$network:$target";
      $origin = "$network/$target";
    } else {
      $event_type = $command eq 'PRIVMSG' ? 'chat.dm_message' : 'chat.dm_notice';
      $object_type = 'chat.dm';
      $object_id = "irc:$network:dm:$target";
      $origin = "$network/$target";
    }

    $body = {
      text => $text,
    };
  }

  my @tags = (
    [ 'overnet_v',  $self->{overnet_version} ],
    [ 'overnet_et', $event_type ],
    [ 'overnet_ot', $object_type ],
    [ 'overnet_oid', $object_id ],
  );

  push @tags, [ 'd', $object_id ] if $kind == 37800;

  my @limitations = ('unsigned', 'no_edit_history');
  push @limitations, 'synthetic_identity'
    unless exists $irc_identity{account};

  $body->{irc_identity} = { %irc_identity }
    if %irc_identity;

  return {
    valid => 1,
    event => {
      kind       => $kind,
      created_at => $created_at + 0,
      tags       => \@tags,
      content => $JSON->encode({
        provenance => {
          type              => 'adapted',
          protocol          => 'irc',
          origin            => $origin,
          external_identity => $nick,
          limitations       => \@limitations,
        },
        body => $body,
      }),
    },
  };
}

sub map_message {
  my ($self, %args) = @_;
  return $self->map_input(%args);
}

sub derive {
  my ($self, %args) = @_;
  my $operation = $args{operation};
  my $input = $args{input} || {};

  return _error('derive operation is required')
    unless defined $operation && length $operation;
  return _error('derive input must be an object')
    if ref($input) ne 'HASH';

  if ($operation eq 'channel_presence') {
    return $self->derive_channel_presence(%{$input});
  }
  if ($operation eq 'authoritative_channel_state') {
    return $self->derive_authoritative_channel_state(
      %{$input},
      session_config => $args{session_config},
    );
  }

  return _error("Unsupported derive operation: $operation");
}

sub derive_channel_presence {
  my ($self, %args) = @_;

  my $network = $args{network};
  return _error('IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  return _error('IRC target is required')
    unless defined $target && length $target;
  return _error('Presence target must be a channel')
    unless $target =~ /\A[#&]/;

  my $created_at = $args{created_at};
  return _error('created_at is required')
    unless defined $created_at;

  my $events = $args{events};
  return _error('events must be a non-empty array')
    unless ref($events) eq 'ARRAY' && @{$events};

  my %members;
  my $as_of;

  for my $event (@{$events}) {
    return _error('derived presence events must be objects')
      unless ref($event) eq 'HASH';

    my $command = $event->{command};
    return _error('derived presence event command is required')
      unless defined $command && length $command;

    return _error('derived presence event network mismatch')
      unless defined $event->{network} && $event->{network} eq $network;

    return _error('derived presence event nick is required')
      unless defined $event->{nick} && length $event->{nick};

    return _error('derived presence event created_at is required')
      unless defined $event->{created_at};

    my $nick = $event->{nick};
    my $event_target = $event->{target};
    my %irc_identity;

    for my $field (qw(account user host)) {
      next unless exists $event->{$field};
      return _error("derived presence event $field must be a non-empty string")
        unless defined $event->{$field} && length $event->{$field};
      $irc_identity{$field} = $event->{$field};
    }

    if ($command eq 'JOIN') {
      return _error('JOIN target must be a channel')
        unless defined $event_target && $event_target =~ /\A[#&]/;
      next unless $event_target eq $target;

      $members{$nick} = {
        nick            => $nick,
        %irc_identity,
        last_event_type => 'chat.join',
      };
      $as_of = $event->{created_at}
        if !defined($as_of) || $event->{created_at} > $as_of;
    } elsif ($command eq 'PART') {
      return _error('PART target must be a channel')
        unless defined $event_target && $event_target =~ /\A[#&]/;
      next unless $event_target eq $target;

      delete $members{$nick};
      $as_of = $event->{created_at}
        if !defined($as_of) || $event->{created_at} > $as_of;
    } elsif ($command eq 'QUIT') {
      return _error('QUIT target must be a channel')
        unless defined $event_target && $event_target =~ /\A[#&]/;
      next unless $event_target eq $target;

      delete $members{$nick};
      $as_of = $event->{created_at}
        if !defined($as_of) || $event->{created_at} > $as_of;
    } elsif ($command eq 'KICK') {
      return _error('KICK target must be a channel')
        unless defined $event_target && $event_target =~ /\A[#&]/;
      return _error('KICK target_nick is required')
        unless defined $event->{target_nick} && length $event->{target_nick};
      next unless $event_target eq $target;

      delete $members{$event->{target_nick}};
      $as_of = $event->{created_at}
        if !defined($as_of) || $event->{created_at} > $as_of;
    } elsif ($command eq 'NICK') {
      return _error('NICK new_nick is required')
        unless defined $event->{new_nick} && length $event->{new_nick};
      next unless exists $members{$nick};

      my $member = delete $members{$nick};
      $member->{nick} = $event->{new_nick};
      @{$member}{keys %irc_identity} = values %irc_identity if %irc_identity;
      $member->{last_event_type} = 'irc.nick';
      $members{$event->{new_nick}} = $member;
      $as_of = $event->{created_at}
        if !defined($as_of) || $event->{created_at} > $as_of;
    }
  }

  return _error('derived presence requires at least one relevant observed event')
    unless defined $as_of;

  my $partial = exists $args{partial} ? ($args{partial} ? JSON::PP::true : JSON::PP::false) : JSON::PP::true;
  my @limitations = ('unsigned', 'no_edit_history', 'irc.ephemeral_presence');
  push @limitations, 'irc.partial_membership'
    if $partial;

  my @members = map {
    my %member = %{$members{$_}};
    \%member;
  } sort keys %members;

  my $object_id = "irc:$network:$target";

  return {
    valid => 1,
    event => {
      kind       => 37800,
      created_at => $created_at + 0,
      tags       => [
        [ 'overnet_v', $self->{overnet_version} ],
        [ 'overnet_et', 'irc.channel_presence' ],
        [ 'overnet_ot', 'chat.channel' ],
        [ 'overnet_oid', $object_id ],
        [ 'd', $object_id ],
      ],
      content => $JSON->encode({
        provenance => {
          type           => 'adapted',
          protocol       => 'irc',
          origin         => "$network/$target",
          external_scope => 'channel_membership',
          limitations    => \@limitations,
        },
        body => {
          members => \@members,
          partial => $partial,
          as_of   => $as_of + 0,
        },
      }),
    },
  };
}

sub derive_authoritative_channel_state {
  my ($self, %args) = @_;

  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  return _error('authoritative_channel_state requires session_config.authority_profile = nip29')
    unless ($session_config->{authority_profile} || '') eq 'nip29';

  my $network = $args{network};
  return _error('IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  return _error('IRC target is required')
    unless defined $target && length $target;
  return _error('authoritative_channel_state target must be a channel')
    unless $target =~ /\A[#&]/;

  my ($group_host, $group_id, $error) = _resolve_nip29_group_binding(
    session_config => $session_config,
    target         => $target,
  );
  return _error($error) if defined $error;

  my $authoritative_events = $args{authoritative_events};
  return _error('authoritative_events must be a non-empty array')
    unless ref($authoritative_events) eq 'ARRAY' && @{$authoritative_events};

  my %members;
  my %metadata = (
    closed           => 0,
    moderated        => 0,
    topic_restricted => 0,
  );
  my %pending_invites;
  my @supported_roles;

  for my $raw_event (@{$authoritative_events}) {
    return _error('authoritative events must be objects')
      unless ref($raw_event) eq 'HASH';

    my $event = eval { Net::Nostr::Event->new(%{$raw_event}) };
    return _error('authoritative events must be valid Nostr events')
      unless $event;

    my $event_group_id = Net::Nostr::Group->group_id_from_event($event);
    return _error('authoritative event group mismatch')
      if defined $event_group_id && $event_group_id ne $group_id;

    if ($event->kind == 39000 || $event->kind == 9002) {
      %metadata = (
        %metadata,
        %{_metadata_from_group_event($event)},
      );
      next;
    }

    if ($event->kind == 39001) {
      my $admins = Net::Nostr::Group->admins_from_event($event);
      for my $admin (@{$admins->{admins} || []}) {
        my @roles = _sorted_roles(@{$admin->{roles} || []});
        $members{$admin->{pubkey}} = {
          pubkey => $admin->{pubkey},
          roles  => \@roles,
        };
      }
      next;
    }

    if ($event->kind == 39002) {
      my $member_info = Net::Nostr::Group->members_from_event($event);
      my %snapshot = map { $_ => 1 } @{$member_info->{members} || []};

      for my $pubkey (keys %members) {
        delete $members{$pubkey}
          unless $snapshot{$pubkey};
      }

      for my $pubkey (@{$member_info->{members} || []}) {
        $members{$pubkey} ||= {
          pubkey => $pubkey,
          roles  => [],
        };
      }
      next;
    }

    if ($event->kind == 39003) {
      my $role_info = Net::Nostr::Group->roles_from_event($event);
      @supported_roles = map { $_->{name} } @{$role_info->{roles} || []};
      next;
    }

    if ($event->kind == 9000) {
      my ($target_pubkey, @roles) = _target_and_roles_from_group_member_event($event);
      return _error('put-user event must include one p tag target')
        unless defined $target_pubkey;

      $members{$target_pubkey} = {
        pubkey => $target_pubkey,
        roles  => [ _sorted_roles(@roles) ],
      };
      next;
    }

    if ($event->kind == 9001) {
      my ($target_pubkey) = _target_and_roles_from_group_member_event($event);
      return _error('remove-user event must include one p tag target')
        unless defined $target_pubkey;

      delete $members{$target_pubkey};
      next;
    }

    if ($event->kind == 9009) {
      my ($invite_code, $target_pubkey) = _invite_code_and_target_from_group_invite_event($event);
      return _error('create-invite event must include one code tag')
        unless defined $invite_code;

      $pending_invites{$invite_code} = {
        code => $invite_code,
        (defined $target_pubkey ? (target_pubkey => $target_pubkey) : ()),
      };
      next;
    }

    if ($event->kind == 9021) {
      my $invite_code = _invite_code_from_group_join_request_event($event);
      next unless defined $invite_code;
      next unless exists $pending_invites{$invite_code};

      my $joiner_pubkey = _effective_actor_pubkey_from_group_event($event);
      next unless defined $joiner_pubkey && length $joiner_pubkey;

      my $invite = $pending_invites{$invite_code};
      next if defined $invite->{target_pubkey}
        && $invite->{target_pubkey} ne $joiner_pubkey;

      $members{$joiner_pubkey} ||= {
        pubkey => $joiner_pubkey,
        roles  => [],
      };
      delete $pending_invites{$invite_code};
      next;
    }
  }

  my $channel_modes = '+' . join(
    '',
    grep { $_ }
      ($metadata{closed} ? 'i' : ''),
      ($metadata{moderated} ? 'm' : ''),
      'n',
      ($metadata{topic_restricted} ? 't' : ''),
  );

  my @derived_members = map {
    my $member = $members{$_};
    {
      pubkey                => $member->{pubkey},
      roles                 => [ @{$member->{roles} || []} ],
      presentational_prefix => _presentational_prefix_for_roles($member->{roles}),
    }
  } sort keys %members;

  return {
    valid => 1,
    state => [
      {
        operation         => 'authoritative_channel_state',
        authority_profile => 'nip29',
        object_type       => 'chat.channel',
        object_id         => "irc:$network:$target",
        group_host        => $group_host,
        group_id          => $group_id,
        group_ref         => Net::Nostr::Group->format_id(
          host     => $group_host,
          group_id => $group_id,
        ),
        channel_modes   => $channel_modes,
        supported_roles => [ @supported_roles ],
        members         => \@derived_members,
      },
    ],
  };
}

sub _map_nip29_authoritative_input {
  my ($self, %args) = @_;

  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  my $command = $args{command} || '';
  my $target = $args{target};
  my $created_at = $args{created_at};

  return _error('created_at is required')
    unless defined $created_at;

  my ($group_host, $group_id, $binding_error) = _resolve_nip29_group_binding(
    session_config => $session_config,
    target         => $target,
  );
  return _error($binding_error) if defined $binding_error;

  my $actor_pubkey = $args{actor_pubkey};
  return _error('authoritative NIP-29 mapping requires actor_pubkey')
    unless defined $actor_pubkey && $actor_pubkey =~ /\A[0-9a-f]{64}\z/;
  my $signing_pubkey = $args{signing_pubkey};
  my $authority_event_id = $args{authority_event_id};
  my $authority_sequence = $args{authority_sequence};
  if (defined $signing_pubkey || defined $authority_event_id || defined $authority_sequence) {
    return _error('authoritative NIP-29 delegated signing requires signing_pubkey')
      unless defined $signing_pubkey && $signing_pubkey =~ /\A[0-9a-f]{64}\z/;
    return _error('authoritative NIP-29 delegated signing requires authority_event_id')
      unless defined $authority_event_id && $authority_event_id =~ /\A[0-9a-f]{64}\z/;
    return _error('authoritative NIP-29 delegated signing requires authority_sequence')
      unless defined $authority_sequence && !ref($authority_sequence) && $authority_sequence =~ /\A[1-9]\d*\z/;
  }
  my $event_pubkey = defined $signing_pubkey ? $signing_pubkey : $actor_pubkey;

  if ($command eq 'KICK') {
    my $target_pubkey = $args{target_pubkey};
    return _error('authoritative NIP-29 KICK requires target_pubkey')
      unless defined $target_pubkey && $target_pubkey =~ /\A[0-9a-f]{64}\z/;

    my $event = Net::Nostr::Group->remove_user(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      target     => $target_pubkey,
      created_at => $created_at + 0,
      reason     => defined $args{text} ? $args{text} : '',
    );
    my $event_hash = $event->to_hash;
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );
    return {
      valid => 1,
      event => $event_hash,
    };
  }

  if ($command eq 'INVITE') {
    my $target_pubkey = $args{target_pubkey};
    return _error('authoritative NIP-29 INVITE requires target_pubkey')
      unless defined $target_pubkey && $target_pubkey =~ /\A[0-9a-f]{64}\z/;

    my $invite_code = $args{invite_code};
    return _error('authoritative NIP-29 INVITE requires invite_code')
      unless defined $invite_code && !ref($invite_code) && length($invite_code);

    my $event = Net::Nostr::Group->create_invite(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      code       => $invite_code,
      created_at => $created_at + 0,
      reason     => defined $args{text} ? $args{text} : '',
    );
    my $event_hash = $event->to_hash;
    push @{$event_hash->{tags}}, [ 'p', $target_pubkey ];
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );

    return {
      valid => 1,
      event => $event_hash,
    };
  }

  if ($command eq 'JOIN') {
    my $invite_code = $args{invite_code};
    return _error('authoritative NIP-29 JOIN invite_code must be a non-empty string when supplied')
      if defined($invite_code) && (ref($invite_code) || !length($invite_code));

    my $event = Net::Nostr::Group->join_request(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      created_at => $created_at + 0,
      (defined $invite_code ? (code => $invite_code) : ()),
      reason     => defined $args{text} ? $args{text} : '',
    );
    my $event_hash = $event->to_hash;
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );
    return {
      valid => 1,
      event => $event_hash,
    };
  }

  return _error('Unsupported authoritative IRC command')
    unless $command eq 'MODE';

  my $mode = $args{mode};
  return _error('MODE mode is required')
    unless defined $mode && length $mode;

  if ($mode =~ /\A([+-])([ov])\z/) {
    my ($direction, $mode_letter) = ($1, $2);
    my $target_pubkey = $args{target_pubkey};
    return _error("authoritative NIP-29 MODE $mode requires target_pubkey")
      unless defined $target_pubkey && $target_pubkey =~ /\A[0-9a-f]{64}\z/;

    my $current_roles = $args{current_roles};
    return _error("authoritative NIP-29 MODE $mode requires current_roles")
      unless ref($current_roles) eq 'ARRAY';
    return _error('current_roles must be an array of non-empty strings')
      if grep { !defined($_) || ref($_) || !length($_) } @{$current_roles};

    my $role_name = $mode_letter eq 'o' ? 'irc.operator' : 'irc.voice';
    my %roles = map { $_ => 1 } @{$current_roles};
    if ($direction eq '+') {
      $roles{$role_name} = 1;
    } else {
      delete $roles{$role_name};
    }

    my $event = Net::Nostr::Group->put_user(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      target     => $target_pubkey,
      created_at => $created_at + 0,
      roles      => [ _sorted_roles(keys %roles) ],
    );
    my $event_hash = $event->to_hash;
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );
    return {
      valid => 1,
      event => $event_hash,
    };
  }

  if ($mode =~ /\A([+-])([imt])\z/) {
    my ($direction, $mode_letter) = ($1, $2);
    my $group_metadata = $args{group_metadata} || {};
    return _error('group_metadata must be an object')
      if ref($group_metadata) ne 'HASH';

    my %metadata = %{$group_metadata};
    if ($mode_letter eq 'i') {
      $metadata{closed} = $direction eq '+' ? 1 : 0;
    } elsif ($mode_letter eq 'm') {
      $metadata{moderated} = $direction eq '+' ? 1 : 0;
    } elsif ($mode_letter eq 't') {
      $metadata{topic_restricted} = $direction eq '+' ? 1 : 0;
    }

    my $event = Net::Nostr::Group->edit_metadata(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      created_at => $created_at + 0,
      (defined $metadata{name} ? (name => $metadata{name}) : ()),
      (defined $metadata{picture} ? (picture => $metadata{picture}) : ()),
      (defined $metadata{about} ? (about => $metadata{about}) : ()),
      ($metadata{private} ? (private => 1) : ()),
      ($metadata{closed} ? (closed => 1) : ()),
      ($metadata{restricted} ? (restricted => 1) : ()),
      ($metadata{hidden} ? (hidden => 1) : ()),
    );

    my $event_hash = $event->to_hash;
    push @{$event_hash->{tags}},
      [ 'mode', 'moderated' ]
      if $metadata{moderated};
    push @{$event_hash->{tags}},
      [ 'mode', 'topic-restricted' ]
      if $metadata{topic_restricted};
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );

    return {
      valid => 1,
      event => $event_hash,
    };
  }

  return _error("Unsupported authoritative NIP-29 MODE: $mode");
}

sub _resolve_nip29_group_binding {
  my (%args) = @_;
  my $session_config = $args{session_config} || {};
  my $target = $args{target};

  return (undef, undef, 'authoritative NIP-29 mapping requires session_config.group_host')
    unless defined $session_config->{group_host} && length $session_config->{group_host};
  return (undef, undef, 'authoritative NIP-29 mapping requires session_config.channel_groups')
    unless ref($session_config->{channel_groups}) eq 'HASH';
  return (undef, undef, 'authoritative NIP-29 mapping requires a channel target')
    unless defined $target && length $target && $target =~ /\A[#&]/;
  return (undef, undef, "authoritative NIP-29 mapping has no group binding for $target")
    unless exists $session_config->{channel_groups}{$target};

  my $binding = $session_config->{channel_groups}{$target};
  my $group_id = ref($binding) eq 'HASH'
    ? $binding->{group_id}
    : $binding;
  return (undef, undef, "authoritative NIP-29 binding for $target requires group_id")
    unless defined $group_id && length $group_id;
  return (undef, undef, "authoritative NIP-29 binding for $target uses an invalid group_id")
    unless Net::Nostr::Group->validate_group_id($group_id);

  return ($session_config->{group_host}, $group_id, undef);
}

sub _metadata_from_group_event {
  my ($event) = @_;
  my %metadata = (
    closed           => 0,
    moderated        => 0,
    topic_restricted => 0,
  );

  my $parsed = eval {
    $event->kind == 39000
      ? Net::Nostr::Group->metadata_from_event($event)
      : {};
  } || {};
  $metadata{name} = $parsed->{name}
    if defined $parsed->{name};
  $metadata{picture} = $parsed->{picture}
    if defined $parsed->{picture};
  $metadata{about} = $parsed->{about}
    if defined $parsed->{about};
  $metadata{private} = $parsed->{private} ? 1 : 0
    if exists $parsed->{private};
  $metadata{restricted} = $parsed->{restricted} ? 1 : 0
    if exists $parsed->{restricted};
  $metadata{hidden} = $parsed->{hidden} ? 1 : 0
    if exists $parsed->{hidden};
  $metadata{closed} = $parsed->{closed} ? 1 : 0
    if exists $parsed->{closed};

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 1;
    if ($tag->[0] eq 'closed') {
      $metadata{closed} = 1;
      next;
    }
    next unless $tag->[0] eq 'mode' && @{$tag} >= 2;
    $metadata{moderated} = 1
      if $tag->[1] eq 'moderated';
    $metadata{topic_restricted} = 1
      if $tag->[1] eq 'topic-restricted';
  }

  return \%metadata;
}

sub _target_and_roles_from_group_member_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next unless $tag->[0] eq 'p';
    return ($tag->[1], @{$tag}[2 .. $#$tag]);
  }

  return;
}

sub _invite_code_and_target_from_group_invite_event {
  my ($event) = @_;
  my $invite_code;
  my $target_pubkey;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    $invite_code = $tag->[1]
      if !defined($invite_code) && $tag->[0] eq 'code';
    $target_pubkey = $tag->[1]
      if !defined($target_pubkey) && $tag->[0] eq 'p';
  }

  return ($invite_code, $target_pubkey);
}

sub _invite_code_from_group_join_request_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    return $tag->[1]
      if $tag->[0] eq 'code';
  }

  return undef;
}

sub _effective_actor_pubkey_from_group_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next unless $tag->[0] eq 'overnet_actor';
    return $tag->[1]
      if defined $tag->[1] && $tag->[1] =~ /\A[0-9a-f]{64}\z/;
  }

  return $event->pubkey;
}

sub _apply_delegated_authority_tags {
  my (%args) = @_;
  my $event_hash = $args{event_hash};
  my $signing_pubkey = $args{signing_pubkey};
  return unless defined $signing_pubkey;

  push @{$event_hash->{tags}},
    [ 'overnet_actor', $args{actor_pubkey} ],
    [ 'overnet_authority', $args{authority_event_id} ],
    [ 'overnet_sequence', 0 + $args{authority_sequence} ];
  return;
}

sub _sorted_roles {
  my @roles = @_;
  my %seen;
  @roles = grep { defined $_ && length $_ && !$seen{$_}++ } @roles;
  return sort {
    ($a eq 'irc.operator' ? 0 : $a eq 'irc.voice' ? 1 : 2)
      <=>
    ($b eq 'irc.operator' ? 0 : $b eq 'irc.voice' ? 1 : 2)
      ||
    $a cmp $b
  } @roles;
}

sub _presentational_prefix_for_roles {
  my ($roles) = @_;
  $roles ||= [];
  my %roles = map { $_ => 1 } @{$roles};
  return '@' if $roles{'irc.operator'};
  return '+' if $roles{'irc.voice'};
  return '';
}

sub _error {
  my ($reason) = @_;
  return {
    valid  => 0,
    reason => $reason,
  };
}

1;

=head1 NAME

Overnet::Adapter::IRC - Overnet IRC adapter

=head1 SYNOPSIS

  use Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  my $result = $adapter->map_message(
    command    => 'PRIVMSG',
    network    => 'irc.libera.chat',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'Hello from IRC!',
    created_at => 1744300860,
  );

=head1 DESCRIPTION

This module is the starting point for an Overnet IRC adapter implementation.

Adapter behavior is defined by the Overnet core specification and the IRC adapter
specification.

=head1 METHODS

=head2 new

Creates a new adapter instance.

=head2 map_message

Maps a supported IRC message input into an unsigned Overnet event draft.

The current implementation supports channel and direct-message C<PRIVMSG>,
channel and direct-message C<NOTICE>, channel C<TOPIC>, and channel-context
C<JOIN>, C<PART>, C<QUIT>, C<KICK>, network-scoped C<NICK>, and channel
C<MODE>.

=head2 map_input

Maps a supported IRC input into an unsigned Overnet event draft.

=cut
