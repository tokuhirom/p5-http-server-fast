package Plack::Handler::HTTP::Server::Fast;
use strict;
use HTTP::Server::Fast;

sub new {
    my($class, %args) = @_;
    bless {%args}, $class;
}

sub run {
    my($self, $app) = @_;

    HTTP::Server::Fast::run(
        $self->{port} || 9090,
        $self->{nchild} || 1,
        $app,
    );
}

1;

__END__

=head1 NAME

Plack::Handler::HTTP::Server::Fast - Adapter for HTTP::Server::Fast

=head1 SYNOPSIS

  plackup -s HTTP::Server::Fast --port 9090

=head1 AUTHOR

Tatsuhiko Miyagawa

=head1 SEE ALSO

L<HTTP::Server::Fast>

=cut
