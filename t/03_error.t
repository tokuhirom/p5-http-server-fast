use strict;
use warnings;
use Test::TCP;
use HTTP::Server::Fast;
use Data::Dumper;
use Test::More;
use LWP::UserAgent;

test_tcp(
    client => sub {
        my $port = shift;
        my $ua = LWP::UserAgent->new();
        my $res = $ua->get("http://127.0.0.1:$port");
        is $res->code, 500;
        is $res->message, 500;
        is $res->content, 'internal server error';
        done_testing;
    },
    server => sub {
        my $port = shift;
        HTTP::Server::Fast::run($port, 1, sub {
            return undef;
        });
    },
);

