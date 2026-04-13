package Overnet::Adapter::IRC;

use strict;
use warnings;
use JSON::PP ();

our $VERSION = '0.001';
my $JSON = JSON::PP->new;

sub new {
  my ($class, %args) = @_;
  $args{overnet_version} //= '0.1.0';
  return bless \%args, $class;
}

sub map_input {
  my ($self, %args) = @_;

  my $command = $args{command};
  return _error('IRC command is required')
    unless defined $command && length $command;

  return _error("Unsupported IRC command: $command")
    unless $command eq 'PRIVMSG'
      || $command eq 'NOTICE'
      || $command eq 'TOPIC'
      || $command eq 'JOIN'
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
