#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

WriteMakefile(
  NAME         => 'POE::Component::Client::DNS',
  AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
  ABSTRACT     => 'Non-blocking/concurrent DNS queries using Net::DNS and POE',
  LICENSE      => 'perl',
  VERSION_FROM => 'DNS.pm',
  PM           => { 'DNS.pm' => '$(INST_LIBDIR)/DNS.pm' },
  PREREQ_PM    => {
    'POE'               => 1.007,
    'Net::DNS'          => 0.59,
    'Test::More'        => 0,
		'Test::NoWarnings'  => 0.084,
  },
  META_ADD     => {
    resources  => {
      license    => 'http://dev.perl.org/licenses/',
      repository => 'http://thirdlobe.com/svn/poco-client-dns/trunk'
    },
  },
  dist         => {
    COMPRESS   => 'gzip -9f',
    SUFFIX     => 'gz',
    PREOP      => (
      'svn-log.perl | tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
    ),
  },
);
