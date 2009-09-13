use strict;
use warnings;
use Test::TCP;
use HTTP::Server::Fast;
use Data::Dumper;
use Test::More;

test_tcp(
    client => sub {
        my $port = shift;
        my $sock = IO::Socket::INET->new(
            PeerHost => '127.0.0.1',
            PeerPort => $port,
        ) or die;
        print $sock "GET /foo?bar=baz HTTP/1.0\r\n";
        print $sock "Content-Type: text/plain\r\n";
        print $sock "X-Foo: bar\r\n";
        print $sock "\r\n";
        print $sock "YATTA!!";
        warn $port;
        {
            my $buf = <$sock>;
            is $buf, "HTTP/1.0 200 200\r\n";
               $buf = <$sock>;
            is $buf, "Content-Length:3\r\n";
               $buf = <$sock>;
            is $buf, "Content-Type:text/html\r\n";
               $buf = <$sock>;
            is $buf, "\r\n";
               $buf = <$sock>;
               use Devel::Peek;
               Dump($buf);
            is $buf, "OK!";
        }
        done_testing;
    },
    server => sub {
        my $port = shift;
        HTTP::Server::Fast::run($port, 1, sub {
            my $env = shift;
            is_deeply($env, {
                'REQUEST_METHOD'  => 'GET',
                'SERVER_PROTOCOL' => '1.0',
                'CONTENT_TYPE'    => 'text/plain',
                'QUERY_STRING'    => 'bar=baz',
                'PATH_INFO'       => '/foo',
                'HTTP_X_FOO'      => 'bar'
            });
            return [200, ['Content-Length' => 3, 'Content-Type' => 'text/html'], ['OK!']];
        });
    },
);

