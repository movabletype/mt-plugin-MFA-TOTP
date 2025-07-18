use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../../../t/lib";

use Test::More;
use MT::Test::Env;
use Mock::MonkeyPatch;

use MT::Plugin::MFA::TOTP::Util qw(initialize_recovery_codes);
our $fixed_base32_secret = undef;
my $mock_generate_base32_secret = Mock::MonkeyPatch->patch(
    'MT::Plugin::MFA::TOTP::Util::generate_base32_secret' => sub {
        return $fixed_base32_secret || Mock::MonkeyPatch::ORIGINAL(@_);
    });

my $core_time = \&CORE::time;
our $fixed_time = undef;
sub fixed_time() {
    return $fixed_time || $core_time->();
}
BEGIN {
    no warnings 'redefine';
    undef(*CORE::GLOBAL::time);
    *CORE::GLOBAL::time = \&fixed_time;
}

our $test_env;
BEGIN {
    $test_env = MT::Test::Env->new;
    $ENV{MT_CONFIG} = $test_env->config_file;
}

use MT::Test;
use MT::Test::Permission;
use MT::Test::App;

$test_env->prepare_fixture('db');

my $totp_base32_secret = '12345678901234567890';
my $totp_when          = 1234567890;
my $totp_valid_token   = '219923';

my $user = MT::Author->load(1);
my $app  = MT::Test::App->new('MT::App::CMS');
$app->login($user);

ok $MT::Plugin::MFA::STATUS_KEY;
ok $MT::Plugin::MFA::STATUS_VERIFIED_WITHOUT_SETTINGS;
ok $MT::Plugin::MFA::STATUS_VERIFIED_WITH_SETTINGS;

subtest 'mfa_settings_updated' => sub {
    my $generate_new_secret = sub {
        $user->mfa_totp_base32_secret(undef);
        $user->mfa_totp_recovery_codes(undef);
        $user->save or die $user->errstr;

        {
            local $fixed_base32_secret = $totp_base32_secret;
            $app->get_ok({ __mode => 'mfa_totp_dialog' });    # generate a new secret
        }
    };

    my $session = MT::App::make_session($user);
    $app->{session} = $session->id;

    subtest 'enable' => sub {
        $generate_new_secret->();

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_enable',
            mfa_totp_token => $totp_valid_token,
        });

        $user->refresh;
        is $user->mfa_totp_base32_secret, $totp_base32_secret;
        ok @{ $user->mfa_totp_recovery_codes };

        $session = MT->model('session')->load($session->id);
        is $session->get($MT::Plugin::MFA::STATUS_KEY), $MT::Plugin::MFA::STATUS_VERIFIED_WITH_SETTINGS;
    };

    subtest 'disable' => sub {
        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_disable',
            mfa_totp_token => $totp_valid_token,
        });

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};

        $session = MT->model('session')->load($session->id);
        is $session->get($MT::Plugin::MFA::STATUS_KEY), $MT::Plugin::MFA::STATUS_VERIFIED_WITHOUT_SETTINGS;
    };
};

done_testing();
