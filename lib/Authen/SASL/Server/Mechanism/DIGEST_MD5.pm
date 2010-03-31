package Authen::SASL::Server::Mechanism::DIGEST_MD5;

use strict;
use warnings;

use base 'Authen::SASL::Server::Mechanism';

use Authen::SASL::Server::State;
use Authen::SASL::Server::Result;
use Authen::SASL::Server::ResultType qw(:all);
use Digest::MD5 qw(md5 md5_hex);

__PACKAGE__->name('DIGEST_MD5');

sub new {
    my ($class, %args) = @_;
    my $get_password = $args{get_password};
    unless ($get_password && ref $get_password && ref $get_password eq 'CODE') {
        die "DIGEST_MD5 mechanism needs get_password subroutine reference";
    }
    my $self = bless {
        get_password => $get_password,
    }, $class;
    $self;
}

sub start {
    my $self = shift;
    my $step = $self->SUPER::start();
    $step->param( nonce => _gen_random() );
    $step;
}

sub _gen_random {
    my $digit = 10;
    my @salt = (0..9, 'a'..'z', 'A'..'Z');
    my $str = "";
    for (my $i=0;$i<$digit;$i++) {
        $str .= $salt[int rand(scalar(@salt))];
    }
    $str;
}

sub step {
    my ($self, $state, $client_input) = @_;
    my $step = $state->step;
    if ($step == 1) {
        $state->step(3);
        my $message = sprintf(q{nonce="%s",qop="auth",charset=utf-8,algorithm=md5-sess}, $state->param('nonce'));
        return Authen::SASL::Server::Result->new(
            type    => CONTINUE, 
            message => $message,
        );
    } elsif ($step == 3) {
        my $params = $self->_parse($client_input);
        my $username = $params->{username} || '';
        my $authzid  = $params->{authzid}  || '';
        my $password = $self->{get_password}->($username) || '';
        my $response = $self->_make_response(
            params   => $params,
            username => $username,
            password => $password,
            nonce    => $state->param('nonce'),
            authzid  => $authzid,
            prefix   => "AUTHENTICATE",
        );
        if (exists $params->{response} && $response eq $params->{response}) {
            my $rspauth = $self->_make_response(
                params   => $params,
                username => $username,
                password => $password,
                nonce    => $state->param('nonce'),
                authzid  => $authzid,
            );
            $state->step(5);
            $state->param(username => $username);
            $state->param(authzid  => $authzid);
            return Authen::SASL::Server::Result->new(
                type    => CONTINUE, 
                message => sprintf(q{rspauth=%s}, $rspauth),
            );
        } else {
            return Authen::SASL::Server::Result->new(
                type    => ERROR,
                message => q{not-authorized},
            );
        }
    } elsif ($step == 5) {
        return Authen::SASL::Server::Result->new(
            type  => 'ok', 
            state => $state,
        );
    } else {
        return Authen::SASL::Server::Result->new(
            type    => ERROR,
            state   => $state,
            message => q{Bad protocol},
        );
    }
}

sub _parse {
    my ($self, $text) = @_;
    $text =~ s/(?:\r|\n)//g;
    my $params = {};
    for my $pairs ( split /,/, $text ) {
        my ($key, $value) = split /=/, $pairs;
        $value =~ s/\"(.*)\"/$1/;
        $params->{$key} = $value;
    }
    $params;
}

sub _make_response {
    my ($self, %args) = @_;
    my $params     = $args{params};
    my $user       = $args{username}         || '';
    my $password   = $args{password}         || '';
    my $authzid    = $args{authzid}          || undef;
    my $nonce      = $args{nonce}            || '';
    my $prefix     = $args{prefix}           || '';
    my $realm      = $params->{realm}        || '';
    my $cnonce     = $params->{cnonce}       || '';
    my $digest_uri = $params->{'digest-uri'} || '';
    my $nc         = $params->{nc}           || '';
    my $qop        = $params->{qop}          || '';
    my $A1 = join(":",
        md5(join(":", $user, $realm, $password)),
        defined($authzid) ? ($nonce, $cnonce, $authzid) : ($nonce, $cnonce));
    my $A2 = join(":", $qop eq 'auth'
        ? ($prefix, $digest_uri)
        : ($prefix, $digest_uri, ":00000000000000000000000000000000")
    ); 
    my $response = md5_hex(
        join(":",
            md5_hex($A1),
            $nonce,
            $nc,
            $cnonce,
            $qop,
            md5_hex($A2),
        )
    );
    $response;
}

1;
