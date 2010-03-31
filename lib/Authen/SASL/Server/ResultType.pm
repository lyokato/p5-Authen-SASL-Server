package Authen::SASL::Server::ResultType;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw/OK CONTINUE ERROR/] );
our @EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant OK       => 'ok';
use constant CONTINUE => 'continue';
use constant ERROR    => 'error';

1;
