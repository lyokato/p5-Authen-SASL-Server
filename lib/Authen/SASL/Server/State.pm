package Authen::SASL::Server::State;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(step));

sub new {
    my ($class, %args) = @_;
    my $step = delete $args{step} || 0;
    my $self = bless {
        step   => $step,
        params => {%args},
    }, $class;
}

sub param {
    my ($self, $name, $value) = @_;
    if ($value) {
        $self->{params}{$name} = $value;
    }
    $self->{params}{$name};
}

1;
