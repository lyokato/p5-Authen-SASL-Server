use strict;
use Test::More tests => 13;

use Authen::SASL::Server::Mechanism::DIGEST_MD5;
use Authen::SASL::Server::ResultType qw(:all);
use Authen::SASL;

my $service = "jabberd";
my $host = "example.org";

my $mech = Authen::SASL::Server::Mechanism::DIGEST_MD5->new(
    get_password => sub {
        my $username = shift; 
        return $username eq 'foo' ? 'bar' : 'buz';
    },
);

my $sasl1 = Authen::SASL->new(
    mechanism => 'DIGEST-MD5',
    callback => {
        user => 'foo',
        pass => 'bar',
    },
);

my $client1 = $sasl1->client_new($service, $host);
my $start1  = $client1->client_start();

my $state1 = $mech->start();
my $result1_1 = $mech->step($state1, $start1);
is($result1_1->type, CONTINUE);
is($result1_1->message, sprintf(q{nonce="%s",qop="auth",charset=utf-8,algorithm=md5-sess},$state1->param('nonce')));
my $answer1_1 = $client1->client_step($result1_1->message);
like($answer1_1, qr{charset=utf-8,cnonce="[0-9a-z]+",digest-uri="jabberd/example.org",nc=00000001,nonce="[0-9a-zA-Z]+",qop=auth,response=[0-9a-zA-F]+,username="foo"});
my $result1_2 = $mech->step($state1, $answer1_1);
is($result1_2->type, CONTINUE);
like($result1_2->message, qr{rspauth=[0-9a-zA-F]+});
my $answer1_2 = $client1->client_step($result1_2->message);
my $result1_3 = $mech->step($state1, $answer1_2);
is($result1_3->type, OK);
is($state1->param('username'), 'foo');
is($state1->param('authzid'), undef);

my $sasl2 = Authen::SASL->new(
    mechanism => 'DIGEST-MD5',
    callback => {
        user => 'foo',
        pass => 'invalid',
    },
);

my $client2 = $sasl2->client_new($service, $host);
my $start2  = $client2->client_start();

my $state2 = $mech->start();
my $result2_1 = $mech->step($state2, $start2);
is($result2_1->type, CONTINUE);
is($result2_1->message, sprintf(q{nonce="%s",qop="auth",charset=utf-8,algorithm=md5-sess}, $state2->param('nonce')));
my $answer2_1 = $client2->client_step($result2_1->message);
like($answer2_1, qr{charset=utf-8,cnonce="[0-9a-z]+",digest-uri="jabberd/example.org",nc=00000001,nonce="[0-9a-zA-Z]+",qop=auth,response=[0-9a-zA-F]+,username="foo"});
my $result2_2 = $mech->step($state2, $answer2_1);
is($result2_2->type, ERROR);
is($result2_2->message, q{not-authorized});
