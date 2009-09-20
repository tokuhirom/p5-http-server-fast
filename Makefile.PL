use inc::Module::Install;
name 'HTTP-Server-Fast';
all_from 'lib/HTTP/Server/Fast.pm';

cc_warnings;
use_ppport 3.19;

cc_append_to_libs 'stdc++';
cc_append_to_ccflags '-O0';
# cc_append_to_ccflags '-DPREFORK';
# cc_append_to_ccflags '-DDEBUG=1';
cc_append_to_ccflags '-DLIMIT_RUNNING=1000';

requires_xs 'XS::Assert'; # will be remove

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
