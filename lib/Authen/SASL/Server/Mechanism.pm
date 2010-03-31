package Authen::SASL::Server::Mechanism;

use strict;
use warnings;

use base 'Class::Data::Accessor';

__PACKAGE__->mk_classaccessor('name');

sub new   { die "virtual" }
sub step  { die "virtual" }

sub start {
    my $self = shift;
    my $step = Authen::SASL::Server::State->new( step => 1 );
    $step;
}


1;
