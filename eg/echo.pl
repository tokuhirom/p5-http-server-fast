use strict;
use warnings;
use HTTP::Server::Fast;
use Devel::Leak;

my $handle;
my $port = 8000;
my $first = Devel::Leak::NoteSV($handle);
HTTP::Server::Fast::run($port, 10, sub {
    [ 200, [ 'Content-Length' => 3, 'Content-Type' => 'text/html' ], ['Hello, world!'] ];
});
my $last = Devel::Leak::CheckSV($handle);
printf "%d - %d\n", $first, $last;
