package MT::Plugin::MFA::TOTP::Util;

use strict;
use warnings;
use utf8;

use MIME::Base32;
use POSIX qw(ceil);
use Crypt::URandom        ();
use MT::Util::Digest::SHA ();
use MT::Plugin::MFA::TOTP::Error;

use Exporter qw/import/;
our @EXPORT_OK = qw(
    generate_base32_secret
    initialize_recovery_codes
    consume_recovery_code
);

my %ALGORITHM_TO_SECRET_LENGTH = (
    "SHA1"   => 20,
    "SHA256" => 34,
    "SHA512" => 64,
);

## _random_bytes and _pseudo_random_bytes were implemented with reference to MT::Util::UniqueID
sub _random_bytes {
    my ($length) = @_;
    eval { Crypt::URandom::urandom($length) } || _pseudo_random_bytes($length);
}

sub _pseudo_random_bytes {
    my ($length) = @_;

    require Math::Random::MT::Perl;
    require Time::HiRes;

    my $bytes = '';
    while (length($bytes) < $length) {
        my $rand = Math::Random::MT::Perl::rand();
        $bytes .= MT::Util::Digest::SHA::sha256($rand . Time::HiRes::time() . $$);
    }

    substr($bytes, 0, $length);
}

## exclude confusing characters 1, l, 0, o from recovery code (32 characters)
sub _generate_recovery_code {
    my ($length) = @_;
    my $code = substr(lc(MIME::Base32::encode_base32(_random_bytes(ceil($length * 5 / 8)))), 0, $length);
    # abcdefghijklmnopqrstuvwxyz234567 -> abcdefghijk8mn9pqrstuvwxyz234567
    $code =~ tr/lo/89/;
    # aaaabbbb -> aaaa-bbbb
    $code =~ s/(.{4})(?=.)/$1-/g;
    $code;
}

sub generate_base32_secret {
    my ($algorithm) = @_;
    my $length = $ALGORITHM_TO_SECRET_LENGTH{$algorithm} or die "Unknown algorithm: $algorithm";
    MIME::Base32::encode_base32(_random_bytes($length));
}

sub initialize_recovery_codes {
    my ($user, $length, $count) = @_;

    $length //= 8;
    $count  //= 8;

    require Math::Random::MT::Perl;

    my @codes = map { _generate_recovery_code($length) } (1 .. $count);
    $user->mfa_totp_recovery_codes(\@codes);
    $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);

    \@codes;
}

sub consume_recovery_code {
    my ($user, $code) = @_;

    $code =~ s/[^a-zA-Z0-9]//g;
    my @user_codes         = @{ $user->mfa_totp_recovery_codes || [] };
    my @non_matching_codes = grep {
        my $user_code = $_;
        $user_code =~ s/[^a-zA-Z0-9]//g;
        $user_code ne $code;
    } @user_codes;
    if (@user_codes == @non_matching_codes) {
        # verify failed
        return;
    }

    $user->mfa_totp_recovery_codes(\@non_matching_codes);
    $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);

    return 1;
}

1;
