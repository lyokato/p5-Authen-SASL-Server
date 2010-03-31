use strict;
use Test::More tests => 9;

use Authen::SASL::Server;
use Authen::SASL::Server::ResultType qw(:all);
use Authen::SASL;

my $server = Authen::SASL::Server->new(
    get_password => sub {
        my $username = shift; 
        return $username eq 'foo' ? 'bar' : 'buz';
    },
    check_password => sub {
        my ($username, $password) = @_; 
        if ($username eq 'foo' && $password eq 'bar') {
            return 1;
        }
        return 0;
    },
);
ok($server->support_mechanisms(qw/PLAIN DIGEST-MD5/), q{load supported mechanisms});
ok(!$server->support_mechanisms(qw/UNKNOWN/), q{should fail to load supported mechanisms});

my $client1_selected_mech = "PLAIN";
my $sasl1 = Authen::SASL->new(
    mechanism => $client1_selected_mech,
    callback => {
        user => 'foo',
        pass => 'bar',
    },
);
my $client1 = $sasl1->client_new;
my $client1_input_text = $client1->client_start;
my $state1 = $server->start($client1_selected_mech);
my $result1 = $server->step($client1_selected_mech, $state1, $client1_input_text);
is($result1->type, OK);

my $sasl2 = Authen::SASL->new(
    mechanism => $client1_selected_mech,
    callback => {
        user => 'foo',
        pass => 'hoge',
    },
);
my $client2 = $sasl2->client_new;
my $client2_input_text = $client2->client_start;
my $state2 = $server->start($client1_selected_mech);
my $result2 = $server->step($client1_selected_mech, $state2, $client2_input_text);
is($result2->type, ERROR);
is($result2->message, q{not-authorized});

my $client3_selected_mech = 'DIGEST-MD5';
my $sasl3 = Authen::SASL->new(
    mechanism => $client3_selected_mech,
    callback => {
        user => 'foo',
        pass => 'bar',
    },
);

my $service = "jabberd";
my $host = "example.org";
my $client3 = $sasl3->client_new($service, $host);
my $client3_input_text = $client3->client_start;
my $state3 = $server->start($client3_selected_mech);
my $result3_1 = $server->step($client3_selected_mech, $state3, $client3_input_text);
is($result3_1->type, CONTINUE);
my $client3_response = $client3->client_step($result3_1->message);
my $result3_2 = $server->step($client3_selected_mech, $state3, $client3_response);
is($result3_1->type, CONTINUE);
my $result3_3 = $server->step($client3_selected_mech, $state3, '');
is($result3_3->type, OK);
is($state3->param('username'), 'foo');
