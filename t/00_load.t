use strict;
use Test::More tests => 6;

BEGIN {
    use_ok("Authen::SASL::Server");
    use_ok("Authen::SASL::Server::Result");
    use_ok("Authen::SASL::Server::State");
    use_ok("Authen::SASL::Server::Mechanism");
    use_ok("Authen::SASL::Server::Mechanism::PLAIN");
    use_ok("Authen::SASL::Server::Mechanism::DIGEST_MD5");
}

