package Authen::SASL::Server::Mechanism::PLAIN;

use strict;
use warnings;

use base 'Authen::SASL::Server::Mechanism';
use Authen::SASL::Server::State;
use Authen::SASL::Server::Result;
use Authen::SASL::Server::ResultType qw(:all);

__PACKAGE__->name('PLAIN');

sub new {
    my ($class, %args) = @_;
    my $check_password = $args{check_password};
    unless ($check_password && ref $check_password && ref $check_password eq 'CODE') {
        die "PLAIN mechanism needs check_password subroutine reference";
    }
    my $self = bless {
        check_password => $check_password, 
    }, $class;
    $self;
}

sub step {
    my ($self, $state, $client_input) = @_;
    $client_input ||= '';
    my @parts = split("\0", $client_input);
    my $authzid  = $parts[0] || '';
    my $user     = $parts[1] || '';
    my $password = $parts[2] || '';
    if ($self->{check_password}->($user, $password)) {
        $state->param( username => $user    );
        $state->param( authzid  => $authzid );
        return Authen::SASL::Server::Result->new( type => OK );
    } else {
        return Authen::SASL::Server::Result->new(
            type    => ERROR,
            message => q{not-authorized},
        );
    }
}

1;
