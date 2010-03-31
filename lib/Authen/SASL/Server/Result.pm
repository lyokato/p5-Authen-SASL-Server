package Authen::SASL::Server::Result;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    type
    message
));

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        type    => undef,
        message => '',
        %args,
    }, $class;
    $self;
}

1;
