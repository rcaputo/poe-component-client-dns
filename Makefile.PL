#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

WriteMakefile
  ( NAME         => 'POE::Component::Client::DNS',
    AUTHOR       => 'Rocco Caputo <troc+poe@netrus.net>',
    ABSTRACT     => 'POE component for non-blocking/concurrent DNS queries.',
    VERSION_FROM => 'POE/Component/Client/DNS.pm',
    dist         => { 'COMPRESS' => 'gzip -9f',
                      'SUFFIX'   => 'gz',
                    },
    PREREQ_PM    => { POE      => 0.11,
                      Net::DNS => 0.12,
                    },
  );
