# Overnet Adapter IRC

Perl implementation workspace for the Overnet IRC adapter.

This dist is intended to implement the IRC adapter specification from `../overnet-spec/docs/adapters/irc.md`.

## Dependency Policy

`Overnet::Adapter::IRC` depends on `Overnet` and must not depend directly on `Net::Nostr`.

## Status

Initial mapping behavior is implemented.

Current supported mappings:

- channel `PRIVMSG` to `chat.message`
- channel `NOTICE` to `chat.notice`
- direct-message `PRIVMSG` to `chat.dm_message`
- direct-message `NOTICE` to `chat.dm_notice`

The adapter currently produces unsigned Overnet event drafts from IRC inputs.

## Development

Run tests with:

```bash
/opt/perl-5.42/bin/prove -Ilib -v t/
```
