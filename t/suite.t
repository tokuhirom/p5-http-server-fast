use Test::Requires qw(Plack::Test::Suite);
use Test::More;

Plack::Test::Suite->run_server_tests('HTTP::Server::Fast');
done_testing;


