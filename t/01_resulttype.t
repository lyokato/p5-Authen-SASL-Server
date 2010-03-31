use strict;
use Test::More tests => 3;

use Authen::SASL::Server::ResultType qw(:all);

is(OK, 'ok');
is(CONTINUE, 'continue');
is(ERROR, 'error');

