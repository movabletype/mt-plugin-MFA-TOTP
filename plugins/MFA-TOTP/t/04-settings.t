use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../extlib", "$FindBin::Bin/../../../t/lib";

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
use MT::Test::App;

$test_env->prepare_fixture('db');

my $totp_base32_secret = '12345678901234567890';
my $totp_when          = 1234567890;
my $totp_valid_token   = '219923';
my $totp_invalid_token = '123456';

my $user = MT::Author->load(1);
my $app  = MT::Test::App->new('MT::App::CMS');

subtest '__mode=mfa_totp_dialog' => sub {
    $app->login($user);

    subtest 'does not have a configured device' => sub {
        subtest 'default issuer' => sub {
            $user->mfa_totp_base32_secret(undef);
            $user->save or die $user->errstr;
            $app->get_ok({
                __mode => 'mfa_totp_dialog',
            });
            $app->content_like(qr/issuer=Movable%20Type/);
            $app->content_like(qr/\Qenable_dialog.min.js\E/);
        };

        subtest 'custom issuer' => sub {
            $user->mfa_totp_base32_secret(undef);
            my $plugin = MT->component('MFA-TOTP');
            $plugin->set_config_value('totp_issuer', 'Example-CMS', 'system');

            $user->mfa_totp_base32_secret(undef);
            $user->save or die $user->errstr;
            $app->get_ok({
                __mode => 'mfa_totp_dialog',
            });
            $app->content_unlike(qr/issuer=Movable%20Type/);
            $app->content_like(qr/issuer=Example-CMS/);
            $app->content_like(qr/\Qenable_dialog.min.js\E/);

            $plugin->reset_config('system');
        };
    };

    subtest 'have a configured device' => sub {
        $user->mfa_totp_base32_secret($totp_base32_secret);
        $user->save or die $user->errstr;
        $app->get_ok({
            __mode => 'mfa_totp_dialog',
        });
        $app->content_like(qr/\Qdisable_dialog.min.js\E/);
    };
};

subtest '__mode=mfa_totp_enable' => sub {
    my $generate_new_secret = sub {
        $app->login($user);

        $user->mfa_totp_base32_secret(undef);
        $user->mfa_totp_recovery_codes(undef);
        $user->save or die $user->errstr;

        {
            local $fixed_base32_secret = $totp_base32_secret;
            $app->get_ok({ __mode => 'mfa_totp_dialog' });    # generate a new secret
        }
    };

    subtest 'success' => sub {
        $generate_new_secret->();

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_enable',
            mfa_totp_token => $totp_valid_token,
        });

        $user->refresh;
        is $user->mfa_totp_base32_secret, $totp_base32_secret;
        ok @{$user->mfa_totp_recovery_codes};
    };

    subtest 'invalid token' => sub {
        $generate_new_secret->();

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_enable',
            mfa_totp_token => $totp_invalid_token,
        });
        like $app->json_error, qr/Security token does not match/;

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};
    };

    subtest 'has a configured device' => sub {
        $generate_new_secret->();

        $user->mfa_totp_base32_secret($totp_base32_secret);

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_enable',
            mfa_totp_token => $totp_valid_token,
        });
        like $app->json_error, qr/Invalid request/;

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};
    };

    subtest 'secret is not generated' => sub {
        $app->login($user);

        $user->mfa_totp_base32_secret(undef);
        $user->mfa_totp_recovery_codes(undef);
        $user->save or die $user->errstr;

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_enable',
            mfa_totp_token => $totp_valid_token,
        });
        like $app->json_error, qr/Invalid request/;

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};
    }
};

subtest '__mode=mfa_totp_disable' => sub {
    my $enable_totp = sub {
        $app->login($user);

        $user->mfa_totp_base32_secret($totp_base32_secret);
        $user->save or die $user->errstr;
        initialize_recovery_codes($user) or die $user->errstr;
    };

    subtest 'disable by security token' => sub {
        $enable_totp->();

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_disable',
            mfa_totp_token => $totp_valid_token,
        });

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};
    };

    subtest 'disable by recovery code' => sub {
        my @recovery_codes = [$enable_totp->()];

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_disable',
            mfa_totp_token => $recovery_codes[0],
        });

        $user->refresh;
        ok !$user->mfa_totp_base32_secret;
        ok !@{$user->mfa_totp_recovery_codes || []};
    };

    subtest 'invalid security token' => sub {
        $enable_totp->();

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_disable',
            mfa_totp_token => $totp_invalid_token,
        });
        like $app->json_error, qr/Security token does not match/;

        $user->refresh;
        is $user->mfa_totp_base32_secret, $totp_base32_secret;
        ok @{$user->mfa_totp_recovery_codes};
    };

    subtest 'invalid recovery code' => sub {
        my @old_recovery_codes = [$enable_totp->()];
        my @recovery_codes = [$enable_totp->()];

        local $fixed_time = $totp_when;
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode         => 'mfa_totp_disable',
            mfa_totp_token => $old_recovery_codes[0],
        });

        $user->refresh;
        is $user->mfa_totp_base32_secret, $totp_base32_secret;
        ok @{$user->mfa_totp_recovery_codes};
    };
};

done_testing();
