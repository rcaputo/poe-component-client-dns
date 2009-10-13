#!/usr/bin/perl
# vim: ts=2 sw=2 filetype=perl expandtab
use warnings;
use strict;

use Test::More tests => 2;
use_ok('POE');
use_ok('POE::Component::Client::DNS');

# idea from Test::Harness, thanks!
diag("Testing Perl $], $^X on $^O");
diag("Testing POE $POE::VERSION");
diag("Testing Net::DNS $Net::DNS::VERSION");
diag("Testing POE::Component::Client::DNS $POE::Component::Client::DNS::VERSION");
