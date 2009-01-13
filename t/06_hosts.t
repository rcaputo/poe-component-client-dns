#!/usr/bin/perl
# $Id$
# vim: filetype=perl

# Test the hosts file stuff.

use warnings;
use strict;
sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::DNS);
use Test::More tests => 3;

require Net::DNS;
my $can_resolve = Net::DNS::Resolver->new->search("poe.perl.org");

use constant HOSTS_FILE => "./test-hosts";

my $resolver = POE::Component::Client::DNS->spawn(
  Alias     => 'named',
  Timeout   => 15,
  HostsFile => HOSTS_FILE,
);

POE::Session->create(
  inline_states  => {
    _start                 => \&start_tests,
    _stop                  => sub { }, # avoid assert problems
    response_no_hosts      => \&response_no_hosts,
    response_hosts_match   => \&response_hosts_match,
    response_hosts_nomatch => \&response_hosts_nomatch,
  }
);

POE::Kernel->run();
exit;

sub start_tests {
  # 1. Test without a hosts file.
  unlink HOSTS_FILE;

  $resolver->resolve(
    event   => "response_no_hosts",
    host    => "poe.perl.org",
    context => "whatever",
  );
}

sub response_no_hosts {
  my $response = $_[ARG0];
  my $address = a_data($response);
  SKIP: {
    skip "Can't resolve with Net::DNS, network probably not available", 1
      unless($can_resolve);
    ok(
      ($address eq "67.207.145.70") || ($address eq "208.97.190.64"),
      "lookup with no hosts file ($address)"
    );
  }

  # 2. Test with a hosts file that contains a host match.
  unlink HOSTS_FILE;  # Changes inode!
  open(HF, ">" . HOSTS_FILE) or die "couldn't write hosts file: $!";
  print HF "123.45.67.89 poe.perl.org\n";
  close HF;

  $resolver->resolve(
    event   => "response_hosts_match",
    host    => "poe.perl.org",
    context => "whatever",
  );
}

sub response_hosts_match {
  my $response = $_[ARG0];
  my $address = a_data($response);
  ok(
    $address eq "123.45.67.89",
    "lookup when hosts file matches ($address)"
  );

  # 3. Test against a hosts file without a host match.
  unlink HOSTS_FILE;  # Changes inode!
  open(HF, ">" . HOSTS_FILE) or die "couldn't write hosts file: $!";
  print HF "123.456.789.012 narf.barf.warf\n";
  close HF;

  $resolver->resolve(
    event   => "response_hosts_nomatch",
    host    => "poe.perl.org",
    context => "whatever",
  );
}

sub response_hosts_nomatch {
  my $response = $_[ARG0];
  my $address = a_data($response);
  SKIP: {
    skip "Can't resolve with Net::DNS, network probably not available", 1
      unless($can_resolve);
    ok(
      ($address eq "67.207.145.70") || ($address eq "208.97.190.64"),
      "lookup with hosts file but no match ($address)"
    );
  }

  unlink HOSTS_FILE;
}

### Not a POE event handler.

sub a_data {
  my $response = shift;
  return "" unless defined $response->{response};

  return (
    grep { ref() eq "Net::DNS::RR::A" } $response->{response}->answer()
  )[0]->rdatastr();
}
