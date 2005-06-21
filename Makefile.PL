#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

WriteMakefile(
  NAME         => 'POE::Component::Client::DNS',
  AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
  ABSTRACT     => 'Non-blocking/concurrent DNS queries using Net::DNS and POE',
  VERSION_FROM => 'DNS.pm',
  PM           => { 'DNS.pm' => '$(INST_LIBDIR)/DNS.pm' },
  PREREQ_PM    => {
    POE        => 0.31,
    Net::DNS   => 0.12,
    Test::More => 0,
  },
  dist         => {
    COMPRESS   => 'gzip -9f',
    SUFFIX     => 'gz',
    PREOP      => (
      'svn-log.perl --repo https://thirdlobe.com/svn/poco-client-dns | ' .
      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
    ),
  },
);
