use inc::Module::Install;
name 'HTTP-Server-Fast';
all_from 'lib/HTTP/Server/Fast.pm';

cc_warnings;
use_ppport 3.19;

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
