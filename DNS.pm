# $Id$
# License and documentation are after __END__.

package POE::Component::Client::DNS;

use strict;

use vars qw($VERSION);
$VERSION = '0.97';

use Carp qw(croak);

use Socket qw(unpack_sockaddr_in inet_ntoa);
use Net::DNS;
use POE;

# Keep track of requests for each response socket.  Used to pass data
# around select_read().

my %req_by_socket;

# Spawn a new PoCo::Client::DNS session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a session.

sub spawn {
  my $type = shift;
  croak "$type requires an even number of parameters" if @_ % 2;
  my %params = @_;

  my $alias = delete $params{Alias};
  $alias = 'resolver' unless $alias;

  my $timeout = delete $params{Timeout};
  $timeout = 90 unless $timeout;

  my $nameservers = delete $params{Nameservers};

  croak(
    "$type doesn't know these parameters: ", join(', ', sort keys %params)
  ) if scalar keys %params;

  POE::Session->create(
    inline_states => {
      _default         => \&poco_dns_default,
      _start           => \&poco_dns_start,
      got_dns_response => \&poco_dns_response,
      resolve          => \&poco_dns_resolve,
      send_request     => \&poco_dns_do_request,
    },
    args => [ $alias, $timeout, $nameservers ],
  );

  undef;
}

# Start the resolver session.  Record the parameters which were
# validated in spawn(), create the internal resolver object, and set
# an alias which we'll be known by.

sub poco_dns_start {
  my ($kernel, $heap, $alias, $timeout, $nameservers) =
    @_[KERNEL, HEAP, ARG0, ARG1, ARG2];

  $heap->{resolver} = Net::DNS::Resolver->new();
  $heap->{timeout}  = $timeout;

  # Set the list of nameservers, if one was supplied.
  $heap->{resolver}->nameservers(@$nameservers)
    if defined($nameservers) and ref($nameservers) eq 'ARRAY';

  $kernel->alias_set($alias);
}

# Receive a request.  This uses extra reference counts to keep the
# client sessions alive until responses are ready.

sub poco_dns_resolve {
  my ($kernel, $heap, $sender, $event, $host, $type, $class) =
    @_[KERNEL, HEAP, SENDER, ARG0, ARG1, ARG2, ARG3];

  my $debug_info =
    "in Client::DNS request at $_[CALLER_FILE] line $_[CALLER_LINE]\n";

  my ($api_version, $context, $timeout);

  # Version 3 API.  Pass the entire request as a hash.
  if (ref($event) eq 'HASH') {
    my %args = %$event;

    $type = delete $args{type};
    $type = "A" unless $type;

    $class = delete $args{class};
    $class = "IN" unless $class;

    $event = delete $args{event};
    die "Must include an 'event' $debug_info" unless $event;

    $context = delete $args{context};
    die "Must include a 'context' $debug_info" unless $context;

    $timeout = delete $args{timeout};

    $host = delete $args{host};
    die "Must include a 'host' $debug_info" unless $host;

    $api_version = 3;
  }

  # Parse user args from the magical $response format.  Version 2 API.

  elsif (ref($event) eq "ARRAY") {
    $context     = $event;
    $event       = shift @$context;
    $api_version = 2;
  }

  # Whee.  Version 1 API.

  else {
    $context     = [ ];
    $api_version = 1;
  }

  # Default the request's timeout.
  $timeout = $heap->{timeout} unless $timeout;

  # Set an extra reference on the sender so it doesn't go away.
  $kernel->refcount_increment($sender->ID, __PACKAGE__);

  # If it's an IN type A request, check /etc/hosts.
  # -><- This is not always the right thing to do, but it's more right
  # more often than never checking at all.

  if ($type eq "A" and $class eq "IN") {
    if (open(HOST, "</etc/hosts")) {
      while (<HOST>) {
        next if /^\s*\#/;
        s/^\s*//;
        chomp;
        my ($address, @aliases) = split;
        next unless grep /^\Q$host\E$/i, @aliases;
        close HOST;

        # Pretend the request went through a name server.

        my $packet = Net::DNS::Packet->new($address, "A", "IN");
        $packet->push(
          "answer",
          Net::DNS::RR->new(
            Name    => $host,
            TTL     => 1,
            Class   => $class,
            Type    => $type,
            Address => $address,
          )
        );

        # Send the response immediately, and return.

        _send_response(
          api_ver  => $api_version,
          sender   => $sender,
          event    => $event,
          host     => $host,
          type     => $type,
          class    => $class,
          context  => $context,
          response => $packet,
          error    => "",
        );

        close HOST;
        return;
      }
      close HOST;
    }
  }

  # We are here.  Yield off to the state where the request will be
  # sent.  This is done so that the do-it state can yield or delay
  # back to itself for retrying.

  my $now = time();
  $kernel->yield(
    send_request => {
      sender    => $sender,
      event     => $event,
      host      => $host,
      type      => $type,
      class     => $class,
      context   => $context,
      started   => $now,
      ends      => $now + $timeout,
      api_ver   => $api_version,
    }
  );
}

# Perform the real request.  May recurse to perform retries.

sub poco_dns_do_request {
  my ($kernel, $heap, $req) = @_[KERNEL, HEAP, ARG0];

  # Did the request time out?
  my $remaining = $req->{ends} - time();
  if ($remaining <= 0) {
    _send_response(
      %$req,
      response => undef,
      error    => "timeout",
    );
    return;
  }

  # Send the request.
  my $resolver_socket = $heap->{resolver}->bgsend(
    $req->{host},
    $req->{type},
    $req->{class}
  );

  # The request failed?  Attempt to retry.

  unless ($resolver_socket) {
    $remaining = 1 if $remaining > 1;
    $kernel->delay_add(send_request => $remaining, $req);
    return;
  }

  # Set a timeout for the request, and watch the response socket for
  # activity.

  $req_by_socket{$resolver_socket} = $req;

  $kernel->delay($resolver_socket, $remaining, $resolver_socket);
  $kernel->select_read($resolver_socket, 'got_dns_response');
}

# A resolver query timed out.  Post an error back.

sub poco_dns_default {
  my ($kernel, $heap, $event, $args) = @_[KERNEL, HEAP, ARG0, ARG1];
  my $socket = $args->[0];

  return unless defined($socket) and $event eq $socket;

  my $req = delete $req_by_socket{$socket};
  return unless $req;

  # Stop watching the socket.
  $kernel->select_read($socket);

  # Post back an undefined response, indicating we timed out.
  _send_response(
    %$req,
    response => undef,
    error    => "timeout",
  );

  # Don't accidentally handle signals.
  return;
}

# A resolver query generated a response.  Post the reply back.

sub poco_dns_response {
  my ($kernel, $heap, $socket) = @_[KERNEL, HEAP, ARG0];

  my $req = delete $req_by_socket{$socket};
  return unless $req;

  # Turn off the timeout for this request, and stop watching the
  # resolver connection.
  $kernel->delay($socket);
  $kernel->select_read($socket);

  # Read the DNS response.
  my $packet = $heap->{resolver}->bgread($socket);

  # Set the packet's answerfrom field, if the packet was received ok
  # and an answerfrom isn't already included.  This uses the
  # documented peerhost() method

  if (defined $packet and !defined $packet->answerfrom) {
    my $answerfrom = getpeername($socket);
    if (defined $answerfrom) {
      $answerfrom = (unpack_sockaddr_in($answerfrom))[1];
      $answerfrom = inet_ntoa($answerfrom);
      $packet->answerfrom($answerfrom);
    }
  }

  # Send the response.
  _send_response(
    %$req,
    response => $packet,
    error    => $heap->{resolver}->errorstring(),
  );
}

# Send a response.  Fake a postback for older API versions.  Send a
# nice, tidy hash for new ones.  Also decrement the reference count
# that's keeping the requester session alive.

sub _send_response {
  my %args = @_;

  # Let the client session go.

  $poe_kernel->refcount_decrement($args{sender}->ID, __PACKAGE__);

  # Simulate a postback for older API versions.

  my $api_version = delete $args{api_ver};
  if ($api_version < 3) {
    $poe_kernel->post(
      $args{sender}, $args{event},
      [ $args{host}, $args{type}, $args{class}, @{$args{context}} ],
      [ $args{response}, $args{error} ],
    );
    return;
  }

  $poe_kernel->post(
    $args{sender}, $args{event},
    {
      host     => $args{host},
      type     => $args{type},
      class    => $args{class},
      context  => $args{context},
      response => $args{response},
      error    => $args{error},
    }
  );
}

1;

__END__

=head1 NAME

POE::Component::Client::DNS - non-blocking, concurrent DNS requests

=head1 SYNOPSIS

  use POE qw(Component::Client::DNS);

  POE::Component::Client::DNS->spawn(Alias => "named");

  POE::Session->create(
    inline_states  => {
      _start   => \&start_tests,
      response => \&got_response,
      _stop => sub { print "bye\n" },
    }
  );

  POE::Kernel->run();
  exit;

  sub start_tests {
    $_[KERNEL]->post(
      named => resolve => {
        event   => "response",
        host    => "localhost",
        context => { },
      },
    );
  }

  sub got_response {
    my $response = $_[ARG0];
    my @answers = $response->{response}->answer();

    # Answers are Net::DNS::Packet objects.
    foreach my $answer (@answers) {
      print(
        "$response->{host} = ",
        $answer->type(), " ",
        $answer->rdatastr(), "\n"
      );
    }
  }

=head1 DESCRIPTION

POE::Component::Client::DNS provides a facility for non-blocking,
concurrent DNS requests.  Using POE, it allows other tasks to run
while waiting for name servers to respond.

=head1 PUBLIC METHODS

=over 2

=item spawn

A program must spawn at least one POE::Component::Client::DNS instance
before it can perform background DNS lookups.  Each instance
represents a connection to a name server, or a pool of them.  If a
program only needs to request DNS lookups from one server, then you
only need one POE::Component::Client::DNS instance.

As of version 0.98 you can override the default timeout per request.
From this point forward there is no need to spawn multiple instances o
affect different timeouts for each request.

PoCo::Client::DNS's C<spawn> method takes a few named parameters:

Alias sets the component's alias.  Requests will be posted to this
alias.  The component's alias defaults to "resolver" if one is not
provided.  Programs spawning more than one DNS client component must
specify aliases for N-1 of them, otherwise alias collisions will
occur.

  Alias => $session_alias,  # defaults to "resolver"

Timeout sets the component's default timeout.  The timeout may be
overridden per request.  See the "request" event, later on.  If no
Timeout is set, the component will wait 90 seconds per request by
default.

Timeouts may be set to real numbers.  Timeouts are more accurate if
you have Time::HiRes installed.  POE (and thus this component) will
use Time::HiRes automatically if it's available.

  Timeout => $seconds_to_wait,  # defaults to 90

Nameservers holds a reference to a list of name servers to try.  The
list is passed directly to Net::DNS::Resolver's nameservers() method.
By default, POE::Component::Client::DNS will query the name servers
that appear in /etc/resolv.conf or its equivalent.

  Nameservers => \@name_servers,  # defaults to /etc/resolv.conf's

=back

=head1 REQUEST MESSAGES

Programs post request events to POE::Component::Client::DNS instances.
The components post responses back, also as events.  The component can
handle three different forms of event, but only one is supported as of
version 0.98.

Requests are posted to the component's "resolve" handler.  They
include several fields, such as the message to return with a response,
the host being resolved, and an optional timeout for the request.
Many of these fields are returned in the response event

  $kernel->post(
    resolver => resolve => {
      class   => $dns_record_class,  # defaults to "IN"
      type    => $dns_record_type,   # defaults to "A"
      host    => $request_host,      # required
      context => $request_context,   # required
      event   => $response_event,    # required
      timeout => $request_timeout,   # defaults to spawn()'s Timeout
    }
  );

The "class" and "type" fields specify what information to return about
a host.  Most of the time internet addresses are requested for host
names, so the class and type default to IN (internet) and A (address),
respectively.

The "host" field designates the host to look up.  It is required.

The "event" field tells the component which event to send back when a
response is available.  It is required.

"timeout" tells the component how long to wait for a response to this
request.  It defaults to the "Timeout" given at spawn() time.

"context" includes some external data that links asynchronous
responses back to their requests.  The data provided by the program
will pass through POE::Component::Client::DNS without modification.
The "context" parameter is required.

Requests include the state to which responses will be posted.  In the
previous example, the handler for a 'got_response' state will be
called with each resolver response.  If the passed through parameter
for 'got_response' is an array reference then the first element will
be treated as the name of the state, and any further elements will be
passed back to the state as arguments.

=head1 RESPONSE MESSAGES

POE::Component::Client::DNS responds by sending messages back to the
requesting sessions.  The message names, and thus the handlers they
trigger, are specified with the "event" parameter in each request.

Responses are hashes, referenced in $_[ARG0].  They contain the
following fields:

  host     => $request_host,
  type     => $request_type,
  class    => $request_class,
  context  => $request_context,
  response => $net_dns_packet,
  error    => $net_dns_error,

The "host", "type", "class", and "context" response fields are
identical to those given in the request message.

"response" contains a Net::DNS::Packet object containing the
resolver's response.  It will be undefined if an error occurred.

"error" contains a description of any error that has occurred.  It is
only valid if "response" is not defined.

=head1 SEE ALSO

L<POE> - This module builds heavily on POE.

L<Net::DNS> - This module uses Net::DNS internally.

L<Net::DNS::Packet> - Responses are returned as Net::DNS::Packet
objects.

=head1 BUGS

This component does not yet expose the full power of Net::DNS.

Timeouts have not been tested extensively.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::DNS is Copyright 1999-2005 by Rocco Caputo.
All rights are reserved.  POE::Component::Client::DNS is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

Postback arguments were contributed by tag.

Rocco may be contacted by e-mail via rcaputo@cpan.org.

=cut
