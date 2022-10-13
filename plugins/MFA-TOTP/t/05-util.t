use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../extlib", "$FindBin::Bin/../../../t/lib";

use Test::More;

use MT::Test::Env;
our $test_env;
BEGIN {
    $test_env = MT::Test::Env->new;
    $ENV{MT_CONFIG} = $test_env->config_file;
}
use MT::Test;
use MT::Test::Permission;

use MT::Plugin::MFA::TOTP::Util qw(
    generate_base32_secret
    initialize_recovery_codes
    consume_recovery_code
);

$test_env->prepare_fixture('db');

subtest 'generate_base32_secret' => sub {
    is length(generate_base32_secret('SHA1')), 32;
    is length(generate_base32_secret('SHA256')), 55;
    is length(generate_base32_secret('SHA512')), 103;
};

subtest 'initialize_recovery_codes' => sub {
    my $user = MT::Test::Permission->make_author;
    my $codes = initialize_recovery_codes($user, 12, 10);
    $user->refresh;
    is @$codes, 10;
    is length($codes->[0]), 12 + 2, '12 chars + 2 hyphens';
    is @{$user->mfa_totp_recovery_codes}, 10;
    is length($user->mfa_totp_recovery_codes->[0]), 12 + 2, 'stored in raw value, not as hash values';
};

subtest 'consume_recovery_code' => sub {
    my $user = MT::Test::Permission->make_author;
    my $codes = initialize_recovery_codes($user, 12, 10);
    $user->refresh;

    ok consume_recovery_code($user, $codes->[0]), 'valid code';
    is @{$user->mfa_totp_recovery_codes}, 9, 'consumed one code';

    ok !consume_recovery_code($user, $codes->[0]), 'must not be consumed same code twice';
    is @{$user->mfa_totp_recovery_codes}, 9, 'not consumed';
};

done_testing();
