use strict;
use Test::More tests => 5;

use Authen::SASL::Server::Result;
use Authen::SASL::Server::ResultType qw(:all);
my $result1 = Authen::SASL::Server::Result->new(
    type => OK,
);
is($result1->type, OK);
my $result2 = Authen::SASL::Server::Result->new(
    type => CONTINUE,
    message => q{next challenge},
);
is($result2->type, CONTINUE);
is($result2->message, q{next challenge});
my $result3 = Authen::SASL::Server::Result->new(
    type => ERROR,
    message => q{error test},
);
is($result3->type, ERROR);
is($result3->message, q{error test});
