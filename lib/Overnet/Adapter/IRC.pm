package Overnet::Adapter::IRC;

use strict;
use warnings;
use JSON::PP ();
use Overnet::Authority::HostedChannel ();
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
      || $command eq 'MODE'
      || $command eq 'DELETE'
      || $command eq 'UNDELETE';

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
      && ($command eq 'KICK' || $command eq 'MODE' || $command eq 'TOPIC' || $command eq 'INVITE' || $command eq 'JOIN' || $command eq 'PART' || $command eq 'DELETE' || $command eq 'UNDELETE')
      && $is_channel_target) {
    return $self->_map_nip29_authoritative_input(
      %args,
      session_config => $session_config,
    );
  }

  return _error("Unsupported IRC command: $command")
    if $command eq 'INVITE' || $command eq 'DELETE' || $command eq 'UNDELETE';

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
  if ($operation eq 'authoritative_channel_view') {
    return $self->derive_authoritative_channel_view(
      %{$input},
      session_config => $args{session_config},
    );
  }
  if ($operation eq 'authoritative_join_admission') {
    return $self->derive_authoritative_join_admission(
      %{$input},
      session_config => $args{session_config},
    );
  }
  if ($operation eq 'authoritative_speak_permission') {
    return $self->derive_authoritative_speak_permission(
      %{$input},
      session_config => $args{session_config},
    );
  }
  if ($operation eq 'authoritative_topic_permission') {
    return $self->derive_authoritative_topic_permission(
      %{$input},
      session_config => $args{session_config},
    );
  }
  if ($operation eq 'authoritative_mode_write_permission') {
    return $self->derive_authoritative_mode_write_permission(
      %{$input},
      session_config => $args{session_config},
    );
  }
  if ($operation eq 'authoritative_channel_action_permission') {
    return $self->derive_authoritative_channel_action_permission(
      %{$input},
      session_config => $args{session_config},
    );
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

  my $view_result = $self->derive_authoritative_channel_view(%args);
  return $view_result unless $view_result->{valid};

  my $view = $view_result->{view}[0];
  return {
    valid => 1,
    state => [
      {
        operation         => 'authoritative_channel_state',
        authority_profile => $view->{authority_profile},
        object_type       => $view->{object_type},
        object_id         => $view->{object_id},
        group_host        => $view->{group_host},
        group_id          => $view->{group_id},
        group_ref         => $view->{group_ref},
        channel_modes     => $view->{channel_modes},
        (ref($view->{ban_masks}) eq 'ARRAY' && @{$view->{ban_masks}} ? (ban_masks => [ @{$view->{ban_masks}} ]) : ()),
        (exists $view->{topic} ? (topic => $view->{topic}) : ()),
        (exists $view->{topic_actor_pubkey} ? (topic_actor_pubkey => $view->{topic_actor_pubkey}) : ()),
        ($view->{tombstoned} ? (tombstoned => JSON::PP::true) : ()),
        supported_roles   => [ @{$view->{supported_roles} || []} ],
        members           => [
          map { +{
            pubkey                => $_->{pubkey},
            roles                 => [ @{$_->{roles} || []} ],
            presentational_prefix => $_->{presentational_prefix},
          } } @{$view->{members} || []}
        ],
        (ref($view->{retained_members}) eq 'ARRAY' ? (
          retained_members => [
            map { +{
              pubkey                => $_->{pubkey},
              roles                 => [ @{$_->{roles} || []} ],
              presentational_prefix => $_->{presentational_prefix},
            } } @{$view->{retained_members}}
          ],
        ) : ()),
      },
    ],
  };
}

sub derive_authoritative_join_admission {
  my ($self, %args) = @_;

  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  return _error('authoritative_join_admission requires session_config.authority_profile = nip29')
    unless ($session_config->{authority_profile} || '') eq 'nip29';

  my $network = $args{network};
  return _error('IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  return _error('IRC target is required')
    unless defined $target && length $target;
  return _error('authoritative_join_admission target must be a channel')
    unless $target =~ /\A[#&]/;

  my ($group_host, $group_id, $error) = _resolve_nip29_group_binding(
    network        => $network,
    session_config => $session_config,
    target         => $target,
  );
  return _error($error) if defined $error;

  my $authoritative_events = $args{authoritative_events};
  return _error('authoritative_events must be an array')
    unless ref($authoritative_events) eq 'ARRAY';

  my $actor_pubkey = $args{actor_pubkey};
  return _error('actor_pubkey must be a 64-character hex pubkey when supplied')
    if defined($actor_pubkey) && (ref($actor_pubkey) || $actor_pubkey !~ /\A[0-9a-f]{64}\z/);
  my $actor_mask = $args{actor_mask};
  return _error('actor_mask must be a non-empty string when supplied')
    if defined($actor_mask) && (ref($actor_mask) || !length($actor_mask));

  my %admission = (
    operation         => 'authoritative_join_admission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => "irc:$network:$target",
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => Net::Nostr::Group->format_id(
      host     => $group_host,
      group_id => $group_id,
    ),
    allowed        => JSON::PP::false,
    member         => JSON::PP::false,
    present        => JSON::PP::false,
    create_channel => JSON::PP::false,
    auth_required  => JSON::PP::false,
    reason         => '',
  );

  if (!@{$authoritative_events}) {
    $admission{allowed} = defined($actor_pubkey) ? JSON::PP::true : JSON::PP::false;
    $admission{create_channel} = defined($actor_pubkey) ? JSON::PP::true : JSON::PP::false;
    $admission{auth_required} = defined($actor_pubkey) ? JSON::PP::false : JSON::PP::true;
    $admission{reason} = defined($actor_pubkey) ? '' : 'auth_required';

    return {
      valid     => 1,
      admission => [ \%admission ],
    };
  }

  my $view_result = $self->derive_authoritative_channel_view(%args);
  return $view_result unless $view_result->{valid};

  my $view = $view_result->{view}[0];
  if (defined($actor_pubkey) && ref($view->{admission}) eq 'HASH') {
    my $present = scalar grep {
      ref($_) eq 'HASH'
        && defined($_->{pubkey})
        && $_->{pubkey} eq $actor_pubkey
    } @{$view->{present_members} || []};

    $admission{allowed} = $view->{admission}{allowed} ? JSON::PP::true : JSON::PP::false;
    $admission{member} = $view->{admission}{member} ? JSON::PP::true : JSON::PP::false;
    $admission{present} = $present ? JSON::PP::true : JSON::PP::false;
    $admission{reason} = defined($view->{admission}{reason}) ? $view->{admission}{reason} : '';
    $admission{invite_code} = $view->{admission}{invite_code}
      if defined $view->{admission}{invite_code};
    $admission{deleted} = JSON::PP::true
      if $view->{admission}{deleted};
  } elsif ($view->{tombstoned}) {
    $admission{deleted} = JSON::PP::true;
    $admission{reason} = 'deleted';
  } else {
    $admission{allowed} = ($view->{channel_modes} || '') =~ /\+[^ ]*i/
      ? JSON::PP::false
      : JSON::PP::true;
    $admission{reason} = ($view->{channel_modes} || '') =~ /\+[^ ]*i/
      ? '+i'
      : '';
  }

  return {
    valid     => 1,
    admission => [ \%admission ],
  };
}

sub derive_authoritative_speak_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $actor_pubkey = $args{actor_pubkey};
  my $member = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles = map { $_ => 1 } @roles;
  my $moderated = ($view->{channel_modes} || '') =~ /\+[^ ]*m/ ? 1 : 0;

  my %permission = (
    operation         => 'authoritative_speak_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    allowed           => JSON::PP::false,
    roles             => [ @roles ],
    presentational_prefix => _presentational_prefix_for_roles(\@roles),
    reason            => '',
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$moderated || $roles{'irc.operator'} || $roles{'irc.voice'}) {
    $permission{allowed} = JSON::PP::true;
  } else {
    $permission{reason} = '+m';
  }

  return {
    valid      => 1,
    permission => [ \%permission ],
  };
}

sub derive_authoritative_topic_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $actor_pubkey = $args{actor_pubkey};
  my $member = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles = map { $_ => 1 } @roles;
  my $topic_restricted = ($view->{channel_modes} || '') =~ /\+[^ ]*t/ ? 1 : 0;

  my %permission = (
    operation         => 'authoritative_topic_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    allowed           => JSON::PP::false,
    reason            => '',
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$topic_restricted || $roles{'irc.operator'}) {
    $permission{allowed} = JSON::PP::true;
  } else {
    $permission{reason} = '+t';
  }

  return {
    valid      => 1,
    permission => [ \%permission ],
  };
}

sub derive_authoritative_mode_write_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $mode = $args{mode};
  return _error('mode is required')
    unless defined($mode) && !ref($mode) && length($mode);
  my $mode_args = $args{mode_args};
  return _error('mode_args must be an array')
    unless ref($mode_args) eq 'ARRAY';

  my $actor_pubkey = $args{actor_pubkey};
  my $member = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles = map { $_ => 1 } @roles;

  my %permission = (
    operation         => 'authoritative_mode_write_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    allowed           => JSON::PP::false,
    mode              => $mode,
    reason            => '',
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$roles{'irc.operator'}) {
    $permission{reason} = 'not_operator';
  } elsif ($mode =~ /\A[+-][ov]\z/) {
    return _error('mode_args[0] target pubkey is required for channel role mode writes')
      unless defined($mode_args->[0]) && !ref($mode_args->[0]) && $mode_args->[0] =~ /\A[0-9a-f]{64}\z/;
    my $target_pubkey = $mode_args->[0];
    my $target_member = _member_for_pubkey($view->{members}, $target_pubkey);
    $permission{allowed} = JSON::PP::true;
    $permission{target_pubkey} = $target_pubkey;
    $permission{current_roles} = ref($target_member) eq 'HASH'
      ? [ @{$target_member->{roles} || []} ]
      : [];
  } elsif ($mode =~ /\A[+-][b]\z/) {
    return _error('mode_args[0] ban mask is required for channel ban mode writes')
      unless defined($mode_args->[0]) && !ref($mode_args->[0]) && length($mode_args->[0]);
    $permission{allowed} = JSON::PP::true;
    $permission{normalized_ban_mask} = $mode_args->[0];
    $permission{group_metadata} = _group_metadata_from_authoritative_view($view);
  } elsif ($mode =~ /\A[+-][imt]\z/) {
    $permission{allowed} = JSON::PP::true;
    $permission{group_metadata} = _group_metadata_from_authoritative_view($view);
  } else {
    return _error('unsupported authoritative channel mode write');
  }

  return {
    valid      => 1,
    permission => [ \%permission ],
  };
}

sub derive_authoritative_channel_action_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $action = $args{action};
  return _error('action is required')
    unless defined($action) && !ref($action) && length($action);
  $action = lc $action;
  return _error('unsupported authoritative channel action')
    unless grep { $_ eq $action } qw(kick invite delete undelete);

  my $actor_pubkey = $args{actor_pubkey};
  my $member = _member_for_pubkey($view->{members}, $actor_pubkey);
  my $retained_member = _member_for_pubkey($view->{retained_members}, $actor_pubkey);
  my @roles = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my @retained_roles = ref($retained_member) eq 'HASH' ? @{$retained_member->{roles} || []} : ();
  my %roles = map { $_ => 1 } @roles;
  my %retained_roles = map { $_ => 1 } @retained_roles;

  my %permission = (
    operation         => 'authoritative_channel_action_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    action            => $action,
    allowed           => JSON::PP::false,
    reason            => '',
  );

  if ($action eq 'undelete') {
    if (!$view->{tombstoned}) {
      $permission{reason} = 'not_deleted';
    } elsif (!$retained_roles{'irc.operator'}) {
      $permission{reason} = 'not_operator';
    } else {
      $permission{allowed} = JSON::PP::true;
      $permission{group_metadata} = _group_metadata_from_authoritative_view($view);
    }
  } elsif ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$roles{'irc.operator'}) {
    $permission{reason} = 'not_operator';
  } else {
    $permission{allowed} = JSON::PP::true;
    if ($action eq 'kick' || $action eq 'invite') {
      return _error('target_pubkey is required for authoritative channel action')
        unless defined($args{target_pubkey}) && !ref($args{target_pubkey}) && $args{target_pubkey} =~ /\A[0-9a-f]{64}\z/;
      $permission{target_pubkey} = $args{target_pubkey};
    }
    if ($action eq 'delete') {
      $permission{group_metadata} = _group_metadata_from_authoritative_view($view);
    }
  }

  return {
    valid      => 1,
    permission => [ \%permission ],
  };
}

sub derive_authoritative_channel_view {
  my ($self, %args) = @_;

  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  return _error('authoritative_channel_view requires session_config.authority_profile = nip29')
    unless ($session_config->{authority_profile} || '') eq 'nip29';

  my $network = $args{network};
  return _error('IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  return _error('IRC target is required')
    unless defined $target && length $target;
  return _error('authoritative_channel_view target must be a channel')
    unless $target =~ /\A[#&]/;

  my ($group_host, $group_id, $error) = _resolve_nip29_group_binding(
    network        => $network,
    session_config => $session_config,
    target         => $target,
  );
  return _error($error) if defined $error;

  my $authoritative_events = $args{authoritative_events};
  return _error('authoritative_events must be a non-empty array')
    unless ref($authoritative_events) eq 'ARRAY' && @{$authoritative_events};
  my $actor_pubkey = $args{actor_pubkey};
  return _error('actor_pubkey must be a 64-character hex pubkey when supplied')
    if defined($actor_pubkey) && (ref($actor_pubkey) || $actor_pubkey !~ /\A[0-9a-f]{64}\z/);
  my $actor_mask = $args{actor_mask};
  return _error('actor_mask must be a non-empty string when supplied')
    if defined($actor_mask) && (ref($actor_mask) || !length($actor_mask));

  my %members;
  my %present_members;
  my %metadata = (
    closed           => 0,
    moderated        => 0,
    topic_restricted => 0,
    ban_masks        => [],
    topic            => undef,
    topic_actor_pubkey => undef,
    tombstoned       => 0,
  );
  my %pending_invites;
  my @supported_roles;

  my @sorted_events = eval { _sorted_authoritative_group_events(@{$authoritative_events}) };
  if ($@) {
    my $error = $@;
    chomp $error;
    return _error($error);
  }

  for my $event (@sorted_events) {
    my $event_group_id = Net::Nostr::Group->group_id_from_event($event);
    return _error('authoritative event group mismatch')
      if defined $event_group_id && $event_group_id ne $group_id;

    if ($event->kind == 39000 || $event->kind == 9002) {
      %metadata = (
        %metadata,
        %{_metadata_from_group_event($event)},
      );
      if ($metadata{tombstoned}) {
        %present_members = ();
        %pending_invites = ();
      }
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
      delete $present_members{$target_pubkey};
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
      my $joiner_pubkey = _effective_actor_pubkey_from_group_event($event);
      next unless defined $joiner_pubkey && length $joiner_pubkey;

      my $joined = 0;
      if (exists $members{$joiner_pubkey}) {
        $joined = 1;
      } elsif (defined $invite_code && exists $pending_invites{$invite_code}) {
        my $invite = $pending_invites{$invite_code};
        next if defined $invite->{target_pubkey}
          && $invite->{target_pubkey} ne $joiner_pubkey;

        $members{$joiner_pubkey} ||= {
          pubkey => $joiner_pubkey,
          roles  => [],
        };
        delete $pending_invites{$invite_code};
        $joined = 1;
      } elsif (!$metadata{closed}) {
        $members{$joiner_pubkey} ||= {
          pubkey => $joiner_pubkey,
          roles  => [],
        };
        $joined = 1;
      }

      $present_members{$joiner_pubkey} = 1 if $joined;
      next;
    }

    if ($event->kind == 9022) {
      my $leaver_pubkey = _effective_actor_pubkey_from_group_event($event);
      next unless defined $leaver_pubkey && length $leaver_pubkey;

      delete $members{$leaver_pubkey};
      delete $present_members{$leaver_pubkey};
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
  my @derived_retained_members = map {
    my $member = $members{$_};
    {
      pubkey                => $member->{pubkey},
      roles                 => [ @{$member->{roles} || []} ],
      presentational_prefix => _presentational_prefix_for_roles($member->{roles}),
    }
  } sort keys %members;
  my @derived_present_members = map {
    my $member = $members{$_}
      or next;
    {
      pubkey                => $member->{pubkey},
      roles                 => [ @{$member->{roles} || []} ],
      presentational_prefix => _presentational_prefix_for_roles($member->{roles}),
    }
  } grep { $present_members{$_} } sort keys %members;
  my @derived_pending_invites = map {
    my %invite = %{$pending_invites{$_}};
    \%invite;
  } sort keys %pending_invites;

  if ($metadata{tombstoned}) {
    @derived_members = ();
    @derived_present_members = ();
    @derived_pending_invites = ();
  }

  my %view = (
    operation         => 'authoritative_channel_view',
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
    (@{$metadata{ban_masks} || []} ? (ban_masks => [ @{$metadata{ban_masks}} ]) : ()),
    (defined($metadata{topic}) ? (topic => $metadata{topic}) : ()),
    (defined($metadata{topic_actor_pubkey}) ? (topic_actor_pubkey => $metadata{topic_actor_pubkey}) : ()),
    supported_roles => [ @supported_roles ],
    members         => \@derived_members,
    present_members => \@derived_present_members,
    pending_invites => \@derived_pending_invites,
    ($metadata{tombstoned} ? (retained_members => \@derived_retained_members) : ()),
    ($metadata{tombstoned} ? (tombstoned => JSON::PP::true) : ()),
  );

  if (defined $actor_pubkey) {
    my $member = $members{$actor_pubkey};
    my $invite = _pending_invite_for_pubkey(\%pending_invites, $actor_pubkey);
    my $banned = !$member && defined($actor_mask)
      ? _actor_mask_is_banned($metadata{ban_masks}, $actor_mask)
      : 0;
    $view{admission} = {
      allowed     => $metadata{tombstoned}
        ? JSON::PP::false
        : ($banned ? JSON::PP::false : ($member || $invite || !$metadata{closed} ? JSON::PP::true : JSON::PP::false)),
      member      => $metadata{tombstoned}
        ? JSON::PP::false
        : ($member ? JSON::PP::true : JSON::PP::false),
      ($metadata{tombstoned} ? (deleted => JSON::PP::true) : ()),
      (!$metadata{tombstoned} && !$banned && defined($invite) ? (invite_code => $invite->{code}) : ()),
      reason      => $metadata{tombstoned}
        ? 'deleted'
        : ($banned ? '+b' : ($member || $invite || !$metadata{closed} ? '' : '+i')),
    };
  }

  return {
    valid => 1,
    view  => [ \%view ],
  };
}

sub _authoritative_permission_view {
  my ($self, %args) = @_;

  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  return (undef, undef, undef, 'authoritative permission derivation requires session_config.authority_profile = nip29')
    unless ($session_config->{authority_profile} || '') eq 'nip29';

  my $network = $args{network};
  return (undef, undef, undef, 'IRC network is required')
    unless defined $network && length $network;

  my $target = $args{target};
  return (undef, undef, undef, 'IRC target is required')
    unless defined $target && length $target;
  return (undef, undef, undef, 'authoritative permission target must be a channel')
    unless $target =~ /\A[#&]/;

  my ($group_host, $group_id, $error) = _resolve_nip29_group_binding(
    network        => $network,
    session_config => $session_config,
    target         => $target,
  );
  return (undef, undef, undef, $error) if defined $error;

  my $authoritative_events = $args{authoritative_events};
  return (undef, undef, undef, 'authoritative_events must be an array')
    unless ref($authoritative_events) eq 'ARRAY';
  return (undef, undef, undef, 'actor_pubkey is required')
    unless defined($args{actor_pubkey}) && !ref($args{actor_pubkey}) && $args{actor_pubkey} =~ /\A[0-9a-f]{64}\z/;
  return (undef, undef, undef, 'authoritative state unavailable')
    unless @{$authoritative_events};

  my $view_result = $self->derive_authoritative_channel_view(%args);
  return (undef, undef, undef, $view_result->{error}) unless $view_result->{valid};
  my $view = $view_result->{view}[0];
  return (undef, undef, undef, 'authoritative channel view is required')
    unless ref($view) eq 'HASH';

  return ($group_host, $group_id, $view, undef);
}

sub _group_metadata_from_authoritative_view {
  my ($view) = @_;
  return {
    closed           => ($view->{channel_modes} || '') =~ /\+[^ ]*i/ ? 1 : 0,
    moderated        => ($view->{channel_modes} || '') =~ /\+[^ ]*m/ ? 1 : 0,
    topic_restricted => ($view->{channel_modes} || '') =~ /\+[^ ]*t/ ? 1 : 0,
    ban_masks        => ref($view->{ban_masks}) eq 'ARRAY' ? [ @{$view->{ban_masks}} ] : [],
    tombstoned       => $view->{tombstoned} ? 1 : 0,
    (exists($view->{topic}) ? (topic => $view->{topic}) : ()),
  };
}

sub _member_for_pubkey {
  my ($members, $pubkey) = @_;
  return undef unless ref($members) eq 'ARRAY';
  return undef unless defined $pubkey && !ref($pubkey) && length($pubkey);

  for my $member (@{$members}) {
    next unless ref($member) eq 'HASH';
    next unless defined $member->{pubkey} && $member->{pubkey} eq $pubkey;
    return $member;
  }

  return undef;
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
    network        => $args{network},
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

    my @events;
    if ($args{create_channel}) {
      my $group_metadata = $args{group_metadata};
      $group_metadata = {}
        unless ref($group_metadata) eq 'HASH';
      my %metadata = %{$group_metadata};
      $metadata{name} = $target
        unless defined $metadata{name} && length($metadata{name});

      push @events,
        _build_group_metadata_event_hash(
          event_pubkey        => $event_pubkey,
          group_id            => $group_id,
          created_at          => $created_at + 0,
          metadata            => \%metadata,
          actor_pubkey        => $actor_pubkey,
          signing_pubkey      => $signing_pubkey,
          authority_event_id  => $authority_event_id,
          authority_sequence  => $authority_sequence,
        ),
        _build_group_put_user_event_hash(
          event_pubkey        => $event_pubkey,
          group_id            => $group_id,
          created_at          => $created_at + 0,
          target_pubkey       => $actor_pubkey,
          roles               => ['irc.operator'],
          actor_pubkey        => $actor_pubkey,
          signing_pubkey      => $signing_pubkey,
          authority_event_id  => $authority_event_id,
          authority_sequence  => $authority_sequence,
        );
    }

    my $event = Net::Nostr::Group->join_request(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
      created_at => $created_at + 0,
      (defined $invite_code ? (code => $invite_code) : ()),
      reason     => defined $args{text} ? $args{text} : '',
    );
    my $event_hash = $event->to_hash;
    push @{$event_hash->{tags}}, [ 'overnet_irc_mask', $args{actor_mask} ]
      if defined $args{actor_mask};
    _apply_delegated_authority_tags(
      event_hash         => $event_hash,
      actor_pubkey       => $actor_pubkey,
      signing_pubkey     => $signing_pubkey,
      authority_event_id => $authority_event_id,
      authority_sequence => $authority_sequence,
    );
    push @events, $event_hash;

    return {
      valid => 1,
      (@events == 1 ? (event => $events[0]) : (events => \@events)),
    };
  }

  if ($command eq 'PART') {
    my $event = Net::Nostr::Group->leave_request(
      pubkey     => $event_pubkey,
      group_id   => $group_id,
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

  if ($command eq 'TOPIC') {
    return _error('TOPIC text is required')
      unless defined $args{text};

    my $group_metadata = $args{group_metadata} || {};
    return _error('group_metadata must be an object')
      if ref($group_metadata) ne 'HASH';

    my %metadata = %{$group_metadata};
    $metadata{topic} = $args{text};

    return {
      valid => 1,
      event => _build_group_metadata_edit_event_hash(
        event_pubkey        => $event_pubkey,
        group_id            => $group_id,
        created_at          => $created_at + 0,
        metadata            => \%metadata,
        actor_pubkey        => $actor_pubkey,
        signing_pubkey      => $signing_pubkey,
        authority_event_id  => $authority_event_id,
        authority_sequence  => $authority_sequence,
      ),
    };
  }

  if ($command eq 'DELETE') {
    my $group_metadata = $args{group_metadata} || {};
    return _error('group_metadata must be an object')
      if ref($group_metadata) ne 'HASH';

    my %metadata = %{$group_metadata};
    $metadata{tombstoned} = 1;

    return {
      valid => 1,
      event => _build_group_metadata_edit_event_hash(
        event_pubkey        => $event_pubkey,
        group_id            => $group_id,
        created_at          => $created_at + 0,
        metadata            => \%metadata,
        actor_pubkey        => $actor_pubkey,
        signing_pubkey      => $signing_pubkey,
        authority_event_id  => $authority_event_id,
        authority_sequence  => $authority_sequence,
      ),
    };
  }

  if ($command eq 'UNDELETE') {
    my $group_metadata = $args{group_metadata} || {};
    return _error('group_metadata must be an object')
      if ref($group_metadata) ne 'HASH';

    my %metadata = %{$group_metadata};
    delete $metadata{tombstoned};

    return {
      valid => 1,
      event => _build_group_metadata_edit_event_hash(
        event_pubkey        => $event_pubkey,
        group_id            => $group_id,
        created_at          => $created_at + 0,
        metadata            => \%metadata,
        actor_pubkey        => $actor_pubkey,
        signing_pubkey      => $signing_pubkey,
        authority_event_id  => $authority_event_id,
        authority_sequence  => $authority_sequence,
      ),
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

  if ($mode =~ /\A([+-])([bimt])\z/) {
    my ($direction, $mode_letter) = ($1, $2);
    my $group_metadata = $args{group_metadata} || {};
    return _error('group_metadata must be an object')
      if ref($group_metadata) ne 'HASH';

    my %metadata = %{$group_metadata};
    if ($mode_letter eq 'b') {
      my $ban_mask = $args{ban_mask};
      return _error("authoritative NIP-29 MODE $mode requires ban_mask")
        unless defined $ban_mask && !ref($ban_mask) && length($ban_mask);

      my %ban_masks = map { $_ => 1 } @{_normalized_ban_masks($metadata{ban_masks})};
      if ($direction eq '+') {
        $ban_masks{$ban_mask} = 1;
      } else {
        delete $ban_masks{$ban_mask};
      }
      $metadata{ban_masks} = [ sort keys %ban_masks ];
    } elsif ($mode_letter eq 'i') {
      $metadata{closed} = $direction eq '+' ? 1 : 0;
    } elsif ($mode_letter eq 'm') {
      $metadata{moderated} = $direction eq '+' ? 1 : 0;
    } elsif ($mode_letter eq 't') {
      $metadata{topic_restricted} = $direction eq '+' ? 1 : 0;
    }

    return {
      valid => 1,
      event => _build_group_metadata_edit_event_hash(
        event_pubkey        => $event_pubkey,
        group_id            => $group_id,
        created_at          => $created_at + 0,
        metadata            => \%metadata,
        actor_pubkey        => $actor_pubkey,
        signing_pubkey      => $signing_pubkey,
        authority_event_id  => $authority_event_id,
        authority_sequence  => $authority_sequence,
      ),
    };
  }

  return _error("Unsupported authoritative NIP-29 MODE: $mode");
}

sub _resolve_nip29_group_binding {
  my (%args) = @_;
  return Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $args{network},
    session_config => $args{session_config},
    target         => $args{target},
  );
}

sub _build_group_metadata_event_hash {
  my (%args) = @_;
  my $metadata = $args{metadata} || {};

  my $event = Net::Nostr::Group->metadata(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    created_at => $args{created_at} + 0,
    (defined $metadata->{name} ? (name => $metadata->{name}) : ()),
    (defined $metadata->{picture} ? (picture => $metadata->{picture}) : ()),
    (defined $metadata->{about} ? (about => $metadata->{about}) : ()),
    ($metadata->{private} ? (private => 1) : ()),
    ($metadata->{closed} ? (closed => 1) : ()),
    ($metadata->{restricted} ? (restricted => 1) : ()),
    ($metadata->{hidden} ? (hidden => 1) : ()),
  );

  my $event_hash = $event->to_hash;
  push @{$event_hash->{tags}},
    [ 'mode', 'moderated' ]
    if $metadata->{moderated};
  push @{$event_hash->{tags}},
    [ 'mode', 'topic-restricted' ]
    if $metadata->{topic_restricted};
  push @{$event_hash->{tags}},
    map { [ 'ban', $_ ] } @{_normalized_ban_masks($metadata->{ban_masks})};
  push @{$event_hash->{tags}},
    [ 'topic', $metadata->{topic} ]
    if exists $metadata->{topic};
  push @{$event_hash->{tags}},
    [ 'status', 'tombstoned' ]
    if $metadata->{tombstoned};

  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
}

sub _build_group_put_user_event_hash {
  my (%args) = @_;

  my $event = Net::Nostr::Group->put_user(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    target     => $args{target_pubkey},
    created_at => $args{created_at} + 0,
    roles      => [ _sorted_roles(@{$args{roles} || []}) ],
  );
  my $event_hash = $event->to_hash;
  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
}

sub _metadata_from_group_event {
  my ($event) = @_;
  my %metadata = (
    closed           => 0,
    moderated        => 0,
    topic_restricted => 0,
    ban_masks        => [],
    topic            => undef,
    topic_actor_pubkey => undef,
    tombstoned       => 0,
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
    if ($tag->[0] eq 'topic') {
      $metadata{topic} = @{$tag} >= 2 ? $tag->[1] : '';
      $metadata{topic_actor_pubkey} = _effective_actor_pubkey_from_group_event($event);
      next;
    }
    if ($tag->[0] eq 'ban' && @{$tag} >= 2) {
      push @{$metadata{ban_masks}}, $tag->[1];
      next;
    }
    if ($tag->[0] eq 'status' && @{$tag} >= 2) {
      $metadata{tombstoned} = 1
        if $tag->[1] eq 'tombstoned';
      next;
    }
    next unless $tag->[0] eq 'mode' && @{$tag} >= 2;
    $metadata{moderated} = 1
      if $tag->[1] eq 'moderated';
    $metadata{topic_restricted} = 1
      if $tag->[1] eq 'topic-restricted';
  }

  $metadata{ban_masks} = _normalized_ban_masks($metadata{ban_masks});
  return \%metadata;
}

sub _build_group_metadata_edit_event_hash {
  my (%args) = @_;
  my $metadata = $args{metadata} || {};

  my $event = Net::Nostr::Group->edit_metadata(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    created_at => $args{created_at} + 0,
    (defined $metadata->{name} ? (name => $metadata->{name}) : ()),
    (defined $metadata->{picture} ? (picture => $metadata->{picture}) : ()),
    (defined $metadata->{about} ? (about => $metadata->{about}) : ()),
    ($metadata->{private} ? (private => 1) : ()),
    ($metadata->{closed} ? (closed => 1) : ()),
    ($metadata->{restricted} ? (restricted => 1) : ()),
    ($metadata->{hidden} ? (hidden => 1) : ()),
  );

  my $event_hash = $event->to_hash;
  push @{$event_hash->{tags}},
    [ 'mode', 'moderated' ]
    if $metadata->{moderated};
  push @{$event_hash->{tags}},
    [ 'mode', 'topic-restricted' ]
    if $metadata->{topic_restricted};
  push @{$event_hash->{tags}},
    map { [ 'ban', $_ ] } @{_normalized_ban_masks($metadata->{ban_masks})};
  push @{$event_hash->{tags}},
    [ 'topic', $metadata->{topic} ]
    if exists($metadata->{topic}) && defined($metadata->{topic});
  push @{$event_hash->{tags}},
    [ 'status', 'tombstoned' ]
    if $metadata->{tombstoned};
  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
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

sub _pending_invite_for_pubkey {
  my ($pending_invites, $pubkey) = @_;
  return undef unless ref($pending_invites) eq 'HASH';
  return undef unless defined $pubkey && !ref($pubkey) && length($pubkey);

  for my $code (sort keys %{$pending_invites}) {
    my $invite = $pending_invites->{$code};
    next unless ref($invite) eq 'HASH';
    next if defined $invite->{target_pubkey} && $invite->{target_pubkey} ne $pubkey;
    return $invite;
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

sub _sorted_authoritative_group_events {
  my @raw_events = @_;
  my @decorated;

  for my $raw_event (@raw_events) {
    die "authoritative events must be objects\n"
      unless ref($raw_event) eq 'HASH';

    my $event = eval { Net::Nostr::Event->new(%{$raw_event}) };
    die "authoritative events must be valid Nostr events\n"
      unless $event;

    my ($authority, $sequence) = _authority_ordering_from_event($event);
    push @decorated, [
      $event->created_at + 0,
      _authoritative_semantic_phase_for_event($event),
      $authority,
      $sequence,
      lc($event->id || ''),
      $event,
    ];
  }

  return map { $_->[5] } sort {
    $a->[0] <=> $b->[0]
      || (
        length($a->[2]) && length($b->[2]) && $a->[2] eq $b->[2] && $a->[3] > 0 && $b->[3] > 0
          ? ($a->[3] <=> $b->[3])
          : 0
      )
      || $a->[1] <=> $b->[1]
      || $a->[4] cmp $b->[4]
  } @decorated;
}

sub _authoritative_semantic_phase_for_event {
  my ($event) = @_;
  my $kind = $event->kind;

  return 0 if $kind == 9000 || $kind == 9002 || $kind == 9009;
  return 1 if $kind == 9021;
  return 2 if $kind == 9001 || $kind == 9022;
  return 3 if $kind == 39000 || $kind == 39001 || $kind == 39002 || $kind == 39003;
  return 4;
}

sub _authority_ordering_from_event {
  my ($event) = @_;
  my $authority = '';
  my $sequence = 0;

  for my $tag (@{$event->tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    if (($tag->[0] || '') eq 'overnet_authority' && !length($authority)) {
      $authority = defined($tag->[1]) && !ref($tag->[1]) ? $tag->[1] : '';
      next;
    }
    if (($tag->[0] || '') eq 'overnet_sequence' && !$sequence) {
      $sequence = (defined($tag->[1]) && !ref($tag->[1]) && $tag->[1] =~ /\A\d+\z/)
        ? 0 + $tag->[1]
        : 0;
    }
  }

  return ($authority, $sequence);
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

sub _normalized_ban_masks {
  my ($ban_masks) = @_;
  return [] unless ref($ban_masks) eq 'ARRAY';

  my %seen;
  return [
    sort grep {
      defined($_) && !ref($_) && length($_) && !$seen{$_}++
    } @{$ban_masks}
  ];
}

sub _actor_mask_is_banned {
  my ($ban_masks, $actor_mask) = @_;
  return 0 unless defined $actor_mask && !ref($actor_mask) && length($actor_mask);

  for my $ban_mask (@{_normalized_ban_masks($ban_masks)}) {
    return 1 if Overnet::Authority::HostedChannel::irc_mask_matches(
      mask  => $ban_mask,
      value => $actor_mask,
    );
  }

  return 0;
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
