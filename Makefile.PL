use strictures 2;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME               => 'Overnet::Adapter::IRC',
  DISTNAME           => 'Overnet-Adapter-IRC',
  AUTHOR             => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT           => 'Perl reference implementation of the Overnet IRC adapter',
  VERSION_FROM       => 'lib/Overnet/Adapter/IRC.pm',
  LICENSE            => 'gpl_3',
  MIN_PERL_VERSION   => '5.040',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 0,
    'strictures'          => 2,
  },
  PREREQ_PM => {
    'JSON'       => 0,
    'Net::Nostr' => 0,
    'Overnet'    => 0.001,
    'strictures' => 2,
  },
  test => {
    TESTS => join(
      ' ',
      qw(
        t/00-load.t
        t/30-nip29-authoritative.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/adapter-irc-perl',
      bugtracker => 'https://github.com/overnet-project/adapter-irc-perl/issues',
    },
  },
);
