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

POE::Component::Client::DNS - a DNS client component

=head1 SYNOPSIS

  use POE qw(Component::Client::DNS);

  POE::Component::Client::DNS->spawn(
    Alias       => 'named',       # defaults to 'resolver'
    Timeout     => 120,           # defaults to 90 seconds
    Nameservers => [ localhost ], # defaults per Net::DNS
  );

  $kernel->post(
    'named',     # posts to the 'named' alias
    'resolve',   # post to named's 'resolve' state
    'postback',  # which of our states will receive responses
    $address,    # the address to resolve
    'A', 'IN'    # the record type and class to return
  );

  # Or

  $kernel->post(named => resolve => [postback => $param], $address,'MX');

  # When the specified postback state is an array reference, it will
  # handle the first element as the name of the postback state, and
  # any following parameters will be passed back in the $_[ARG0]
  # array.

  # This is the sub which is called when the session receives a
  # 'postback' event.
  sub postback_handler {
    my (
      $request_address, $request_type, $request_class,
      @postback_parameters
    ) = @{$_[ARG0]};
    my ($net_dns_packet, $net_dns_errorstring) = @{$_[ARG1]};

    unless (defined $net_dns_packet) {
      print "$request_address: error ($net_dns_errorstring)\n";
      return;
    }

    my @net_dns_answers = $net_dns_packet->answer;

    unless (@net_dns_answers) {
      print "$request_address: no answer\n";
      return;
    }

    foreach my $net_dns_answer (@net_dns_answers) {
      printf( "%25s (%-10.10s) %s\n",
              $request_address,
              $net_dns_answer->type,
              $net_dns_answer->rdatastr
            );
    }
  }

=head1 DESCRIPTION

POE::Component::Client::DNS is a wrapper for non-blocking Net::DNS.
It lets other tasks to run while something is waiting for a nameserver
to respond, and it lets several DNS queries run in parallel.

DNS client components are not proper objects.  Instead of being
created, as most objects are, they are "spawned" as separate sessions.
To avoid confusion (and hopefully not cause other confusion), they
must be spawned with a C<spawn> method, not created anew with a C<new>
one.

PoCo::Client::DNS's C<spawn> method takes a few named parameters:

=over 2

=item Alias => $session_alias

C<Alias> sets the name by which the session will be known.  If no
alias is given, the component defaults to "resolver".  The alias lets
several sessions interact with resolver components without keeping (or
even knowing) hard references to them.  It's possible to spawn several
DNS components with different names.

=item Timeout => $resolve_timeout

C<Timeout> specifies the amount of time a DNS client component will
wait for a response.  C<$resolve_timeout> holds a real number
indicating how many seconds to wait.  It's possible to wait for
fractional seconds with it whether or not Time::HiRes is installed,
but installing Time::HiRes will make the actual timeouts more
accurate.  The default timeout period is 90 seconds.

=item Nameservers => \@name_servers

C<Nameservers> holds a reference to a list of nameservers to try.  The
nameservers are passed directly to Net::DNS::Resolver's C<nameservers>
method.  Net::DNS::Resolver's default nameservers are the ones that
occur in /etc/resolv.conf or its local equivalent.

=back

Sessions communicate asynchronously with PoCo::Client::DNS.  They post
requests to it, and it posts responses back.

Requests are posted to the component's "resolve" state.  They include
the name of a state to post responses back to, an address to look up,
and a reference to a list of record types to return.  For example:

  $kernel->post(resolver => resolve => # resolver session alias & state
           [ got_response => $param ], # my state to receive responses
              'poe.perl.org',          # look up poe.perl.org
              'ANY'                    # return any IN records found
            );

Requests include the state to which responses will be posted.  In the
previous example, the handler for a 'got_response' state will be
called with each resolver response.  If the passed through parameter
for 'got_response' is an array reference then the first element will
be treated as the name of the state, and any further elements will be
passed back to the state as arguments.

Resolver responses come with two list references:

  my ($request_packet, $response_packet) = @_[ARG0, ARG1];

C<$request_packet> contains the address and record types from the
original request, and any user specified parameters for postback:

  my ($request_address, $request_type, $request_class, @params) = 
      @$request_packet;

C<$response_packet> contains two things: a reference to a
Net::DNS::Packet object (or undef on error), and the last
Net::DNS::Resolver error string (which describes why the packet
reference might be undef).

  my ($response_packet, $response_error) = @$response_packet;

Please see the Net::DNS::Packet manpage for more information about DNS
packets and their contents.  The PoCo::Client::DNS test program is
also a good example for using Net::DNS::Packet objects.

=head1 SEE ALSO

This component is built upon Net::DNS and POE.  Please see its source
code and the documentation for its foundation modules to learn more.

Also see the test program, t/01_resolve.t, in the PoCo::Client::DNS
distribution.

=head1 BUGS

This component does not yet expose the full power of Net::DNS.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::DNS is Copyright 1999-2002 by Rocco Caputo.
All rights are reserved.  POE::Component::Client::DNS is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

Postback arguments were contributed by tag.

Rocco may be contacted by e-mail via rcaputo@cpan.org.

=cut
