use strict;
use warnings;
use HTTP::Server::Fast;

my $port = 8000;
HTTP::Server::Fast::run($port, 1, sub {
    my $env = shift;
    return [ 200, [ 'Content-Length' => 3, 'Content-Type' => 'text/html' ], ['Hello, world!'] ];
});

