#!/usr/bin/perl -w
# $Id$

# Deliberately trigger errors.

use strict;
use POE qw(Component::Client::DNS);

use Test::More tests => 9;

# Avoid a warning.
POE::Kernel->run();

sub test_err {
  my ($err, $target) = @_;
  $err =~ s/ at \S+ line \d+.*//s;
  ok($err eq $target, $target);
}

eval { POE::Component::Client::DNS->spawn(1); };
test_err(
  $@,
  "POE::Component::Client::DNS requires an even number of parameters"
);

eval { POE::Component::Client::DNS->spawn(moo => "nope"); };
test_err(
  $@,
  "POE::Component::Client::DNS doesn't know these parameters: moo"
);

my $resolver = POE::Component::Client::DNS->spawn();

eval {
  $poe_kernel->call(
    "resolver", "resolve", {
    }
  );
};
test_err($@, "Must include an 'event' in Client::DNS request");

eval {
  $poe_kernel->call(
    "resolver", "resolve", {
      event => "moo",
    }
  );
};
test_err($@, "Must include a 'context' in Client::DNS request");

eval {
  $poe_kernel->call(
    "resolver", "resolve", {
      event   => "moo",
      context => "bar",
    }
  );
};
test_err($@, "Must include a 'host' in Client::DNS request");

eval {
  $resolver->resolve(1);
};
test_err($@, "resolve() needs an even number of parameters");

eval {
  $resolver->resolve();
};
test_err($@, "resolve() must include an 'event'");

eval {
  $resolver->resolve(
    event => "moo",
  );
};
test_err($@, "resolve() must include a 'context'");

eval {
  $resolver->resolve(
    event   => "moo",
    context => "bar",
  );
};
test_err($@, "resolve() must include a 'host'");
