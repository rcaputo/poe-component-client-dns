#!/usr/bin/perl -w
# tag@cpan.org

use strict;
use POE qw(Component::Client::DNS);
use Data::Dumper;

print "1..4\n";

my $reverse = "127.0.0.1";

POE::Component::Client::DNS->spawn(
  Alias   => 'named',
  Timeout => 5,
);

my @tests = ("not ") x 4;
my $test_number = 0;

POE::Session->create(
  inline_states  => {
    _start => sub {
      for (1..4) {
        $_[KERNEL]->post(
          named => resolve =>
          [ reverse => "TEST WORKED", $test_number++ ] =>
          $reverse, 'PTR'
        );
      }
    },

    _stop => sub { }, # for asserts

    reverse => sub {
      if ($_[ARG0][3] eq "TEST WORKED") {
        $tests[$_[ARG0][4]] = "";
      }
    },
  }
);

POE::Kernel->run;

for (1..@tests) {
  print shift(@tests), "ok $_\n";
}

exit 0;
