package MT::Plugin::MFA::TOTP::Util;

use strict;
use warnings;
use utf8;

use MIME::Base32;
use POSIX qw(ceil);
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

my $RECOVERY_CODE_LENGTH = 8;
my $RECOVERY_CODE_COUNT  = 8;

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
    if (length($bytes) < $length) {
        my $rand = Math::Random::MT::Perl::rand();
        $bytes .= MT::Util::Digest::SHA::sha256($rand . Time::HiRes::time() . $$);
    }

    substr($bytes, 0, $length);
}

## exclude confusing characters 1, l, 0, o from recovery code (32 characters)
sub _generate_recovery_code {
    my $code = lc(MIME::Base32::encode_base32(_random_bytes(ceil($RECOVERY_CODE_LENGTH * 5 / 8))));
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

sub _code_to_hash_value {
    my ($code) = @_;
    $code =~ s/[^a-zA-Z0-9]//g;
    MT::Util::Digest::SHA::sha512_hex($code);
}

sub initialize_recovery_codes {
    my ($user) = @_;

    require Math::Random::MT::Perl;

    my @codes = map { _generate_recovery_code() } (1 .. $RECOVERY_CODE_COUNT);
    $user->mfa_totp_recovery_codes(join(',', map { _code_to_hash_value($_) } @codes));
    $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);

    \@codes;
}

sub _get_recovery_codes {
    my ($user) = @_;
    my $codes = $user->mfa_totp_recovery_codes;
    $codes ? [split(',', $codes)] : [];
}

sub consume_recovery_code {
    my ($user, $code) = @_;

    $code = _code_to_hash_value($code);
    my @codes              = @{ _get_recovery_codes($user) };
    my @non_matching_codes = grep { $_ ne $code } @codes;
    if (@codes == @non_matching_codes) {
        # verify failed
        return;
    }

    $user->mfa_totp_recovery_codes(join(',', @non_matching_codes));
    $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);

    return 1;
}

1;
