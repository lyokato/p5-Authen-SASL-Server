package Authen::SASL::Server;

use strict;
use warnings;

use base 'Class::ErrorHandler';
use UNIVERSAL::require;

our $VERSION = '0.01';

=head1 NAME

Authen::SASL::Server - SASL server pure-perl implementation

=head1 SYNOPSIS

    my $sasl_server = Authen::SASL::Server->new(
        check_password => sub {
            my ($username, $password) = @_; 
            if ( username_and_password_is_correct($username, $password) ) {
                return 1;
            } else {
                return 0;
            }
        },
        get_password => sub {
            my ($username) = @_; 
            my $password = get_password_from_username($username);
            return $password;
        },
    );
    $sasl_server->support_mechanism('DIGEST-MD5');
    $sasl_server->support_mechanisms(qw/PLAIN DIGEST-MD5/);

    my $client_selected_mech = 'DIGEST-MD5';
    my $state = $sasl_server->start($client_selected_mech)
        or die $sasl_server->errstr;

    my $result = $sasl_server->step($client_selected_mech, $state, $client_input)
        or die $sasl_server->errstr;

    use Authen::SASL::Server::ResultType qw(OK CONTINUE ERROR);

    if ($result->type eq OK) {
        $your_app->complete_sasl_authentication();
    } elsif ($result->type eq CONTINUE) {
        $your_app->save_sasl_state($client_id => $state);
        $your_app->send_next_challenge($result->message);
    } elsif ($result->type eq ERROR) {
        $your_app->send_error_message($result->message);
    }

=head1 DESCRIPTION

=head1 METHODS

=head2 $class->new(%args)

    my $server = Authen::SASL::Server->new(
        get_password => sub {}, 
        check_password => sub {},
    );

=over 4

=item get_password

Recieved a username as first argument, and should return a password of a user who matched the name.

=item check_password

Recieved a username and a password, and if the pair is correct, should return 1.

=back
    
=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        get_password         => $args{get_password},
        check_password       => $args{check_password},
        supported_mechanisms => {},
    }, $class;
    $self;
}

=head2 $self->support_mechanism($mechanism)

    $self->support_mechanism('PLAIN')
        or die $self->errstr;

=cut

sub support_mechanism {
    my ($self, $mech) = @_;
    $mech =~ s/\-/_/g;
    my $mech_class = "Authen::SASL::Server::Mechanism::".$mech;
    $mech_class->require
        or return $self->error(qq{no mechanism});
    return 1 if exists $self->{supported_mechanisms}{$mech_class->name};
    my $mech_obj = $mech_class->new(
        get_password   => $self->{get_password},
        check_password => $self->{check_password},
    );
    $self->{supported_mechanisms}{$mech_class->name} = $mech_obj;
    return 1;
}

=head2 $self->support_mechanisms(@mechanisms)

    $self->support_mechanisms(qw/PLAINTEXT DIGEST-MD5/)
        or die $self->errstr;

=cut

sub support_mechanisms {
    my ($self, @mechs) = @_;
    $self->support_mechanism($_) or return for @mechs;
    return 1;
}

=head2 $server->start($mechanism);

Initialte SASL authentication process.
Returns L<Authen::SASL::Server::State> object.

    my $state = $server->start($mechanism)
        or die $server->errstr;

=cut

sub start {
    my ($self, $selected_mech) = @_;
    my $mech = $self->_get_mech($selected_mech) or return;
    my $state = $mech->start();
    return $state;
}

=head2 $server->step($mechanism, $client_input_text);

Returns L<Authen::SASL::Server::Result> object.

    use Authen::SASL::Server::ResultType qw(OK CONTINUE ERROR);
    my $result = $server->step($mechanism, $client_input_text)
        or die $server->errstr;
    if ($result->type eq OK) {
        $your_app->complete_sasl_authentication();
    } elsif ($result->type eq CONTINUE) {
        $your_app->send_next_challenge($result->message);
    } elsif ($result->type eq ERROR) {
        $your_app->send_error_message($result->message);
    }

=cut

sub step {
    my ($self, $mech_name, $state, $client_input) = @_;
    my $mech = $self->_get_mech($mech_name) or return;
    $mech->step($state, $client_input);
}

sub _get_mech {
    my ($self, $selected_mech) = @_;
    $selected_mech =~ s/-/_/;
    unless (exists $self->{supported_mechanisms}{$selected_mech}) {
        return $self->error(qq{no mechanism});
    }
    $self->{supported_mechanisms}{$selected_mech};
}

=head1 SEE ALSO

L<Authen::SASL>

=head1 AUTHOR

Lyo Kato, C<lyo.kato _at_ gmail.com>

=head1 COPYRIGHT AND LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
