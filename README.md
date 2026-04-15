# Overnet Adapter IRC

Perl implementation workspace for the Overnet IRC adapter.

This dist is intended to implement the IRC adapter specification from `../overnet-spec/docs/adapters/irc.md`.

## Dependency Policy

`Overnet::Adapter::IRC` depends on `Overnet` and MAY also depend directly on `Net::Nostr` when the IRC adapter specification requires explicit Nostr or NIP behavior such as `NIP-29`.

Overnet programs are the layer that SHOULD NOT depend directly on `Net::Nostr`. Programs should rely on `Overnet::*` components instead.

## Status

Initial mapping behavior is implemented.

Current supported mappings:

- channel `PRIVMSG` to `chat.message`
- channel `NOTICE` to `chat.notice`
- channel `TOPIC` to `chat.topic`
- channel `JOIN` to `chat.join`
- channel `PART` to `chat.part`
- channel-context `QUIT` to `chat.quit`
- channel `KICK` to `chat.kick`
- channel `MODE` to `irc.mode`
- direct-message `PRIVMSG` to `chat.dm_message`
- direct-message `NOTICE` to `chat.dm_notice`
- network `NICK` to `irc.nick`
- optional identity enrichment in `body.irc_identity`
- optional authoritative `NIP-29` event drafts for hosted-channel `KICK` and writable `MODE`
- optional derived authoritative IRC channel state from `NIP-29` group events

The adapter currently produces unsigned Overnet event drafts from IRC inputs.

The current design goal is fidelity to IRC semantics first. Observed IRC actions are preserved as adapted events and are not automatically treated as native Overnet authority or derived canonical state.

## Development

Run tests with:

```bash
/opt/perl-5.42/bin/prove -Ilib -v t/
```
