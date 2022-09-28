package MT::Plugin::MFA::TOTP::Error;

use strict;
use warnings;
use utf8;

use overload '""' => sub { shift->{message} }, fallback => 1;

sub new {
    my ($class, $message) = @_;
    bless { message => $message }, $class;
}

1;
