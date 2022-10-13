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

__END__

=head1 NAME

MT::Plugin::MFA::TOTP::Error - Error object used by this plugin.

=head1 SYNOPSIS

    use MT::Plugin::MFA::TOTP::Error;

    # Errors on save are logged in MT::Object, so errstr contains errors that can be displayed.
    $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);

=head1 DESCRIPTION

Error details are already logged by MT::Util::Log, etc.,
and only messages that can be displayed to the user are retained.
