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
