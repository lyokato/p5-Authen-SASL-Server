use strict;
use Test::More tests => 7;

use Authen::SASL::Server::State;

my $state = Authen::SASL::Server::State->new();
is($state->step, 0);

$state->param( another1 => 'foo' );
$state->param( another2 => 'bar' );

is($state->param('another1'), 'foo');
is($state->param('another2'), 'bar');
is($state->param('unknown'), undef);

my $state2 = Authen::SASL::Server::State->new( step => 1 );
is($state2->step, 1);

my $state3 = Authen::SASL::Server::State->new(
    step => 1,
    buz  => q{qwerty},
);

is($state3->step, 1);
is($state3->param('buz'), q{qwerty});
