use strict;
use Test::More tests => 12;

use Authen::SASL::Server::Mechanism::PLAIN;
use Authen::SASL::Server::ResultType qw(:all);
use Authen::SASL;

eval {
    Authen::SASL::Server::Mechanism::PLAIN->new();
};
ok($@, q{should to fail without check_password});

my $mech = Authen::SASL::Server::Mechanism::PLAIN->new(
    check_password => sub {
        my ($username, $password) = @_; 
        if ($username && $username eq 'foo'
         && $password && $password eq 'bar') {
            return 1;
        } else {
            return 0;
        }
    },
);

my $sasl1 = Authen::SASL->new(
    mechanism => 'PLAIN',
    callback => {
        user => 'foo',
        pass => 'bar',
    }
);
my $client1 = $sasl1->client_new;
my $start1 = $client1->client_start();
is($start1, join("\0", '', qw(foo bar)));
my $state1  = $mech->start();
my $result1 = $mech->step($state1, $start1);
is($result1->type, OK);
is($state1->param('username'), 'foo');
is($state1->param('authzid'), undef);

my $sasl2 = Authen::SASL->new(
    mechanism => 'PLAIN',
    callback => {
        user => 'foo',
        pass => 'invalid',
    },
);
my $client2 = $sasl2->client_new;
my $start2 = $client2->client_start();
my $state2 = $mech->start();
my $result2 = $mech->step($state2, $start2);
is($result2->type, ERROR);
is($result2->message, q{not-authorized});

my $sasl3 = Authen::SASL->new(
    mechanism => 'PLAIN',
    callback => {
        authname => 'myauthzid',
        user     => 'foo',
        pass     => 'bar',
    },
);
my $client3 = $sasl3->client_new;
my $start3 = $client3->client_start();
my $state3 = $mech->start();
my $result3 = $mech->step($state3, $start3);
is($result3->type, OK);
is($state3->param('username'), 'foo');
is($state3->param('authzid'), 'myauthzid');

my $sasl4 = Authen::SASL->new(
    mechanism => 'PLAIN',
    callback => {
        authname => 'myauthzid',
        user     => 'foo',
        pass     => 'invalid',
    },
);
my $client4 = $sasl4->client_new;
my $start4 = $client4->client_start();
my $state4 = $mech->start();
my $result4 = $mech->step($state4, $start4);
is($result4->type, ERROR);
is($result4->message, q{not-authorized});
