#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

WriteMakefile
  ( NAME         => 'POE::Component::Client::DNS',
    AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
    ABSTRACT     => 'POE component for non-blocking/concurrent DNS queries.',
    VERSION_FROM => 'DNS.pm',

    PM           => { 'DNS.pm' => '$(INST_LIBDIR)/DNS.pm' },
    PREREQ_PM    => { POE      => 0.11,
                      Net::DNS => 0.12,
                    },
    dist         =>
    { COMPRESS   => 'gzip -9f',
      SUFFIX     => 'gz',
      PREOP      => ( 'cvs-log.perl | ' .
                      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
                    ),
    },
  );
