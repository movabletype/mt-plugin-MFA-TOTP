use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../extlib", "$FindBin::Bin/../../../t/lib";

use Test::More;
use MT::Test::Env;

use MT::Plugin::MFA::TOTP::Util qw(initialize_recovery_codes consume_recovery_code);

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

my $totp_base32_secret = '1234567890123456789012345678901234567890123456789012345678901234';
my $totp_when          = 1234567890;
my $totp_valid_token   = '434605';
my $totp_invalid_token = '123456';

my $password = 'password';
my $user     = MT::Author->load(1);
$user->set_password($password);
$user->save or die $user->errstr;

my $totp_user = MT::Test::Permission->make_author;
$totp_user->set_password($password);
$totp_user->mfa_totp_base32_secret($totp_base32_secret);
$totp_user->save                      or die $totp_user->errstr;
initialize_recovery_codes($totp_user) or die $totp_user->errstr;

my $app = MT::Test::App->new('MT::App::CMS');

sub insert_failedlogin {
    my ($user) = @_;
    my $failedlogin = MT->model('failedlogin')->new;
    $failedlogin->author_id($user->id);
    $failedlogin->remote_ip('127.0.0.1');
    $failedlogin->start(time);
    $failedlogin->save or die $failedlogin->errstr;
}

subtest 'sign in' => sub {
    subtest 'does not have a configured device' => sub {
        subtest 'valid password' => sub {
            $app->post_ok({
                username => $user->name,
                password => $password,
            });
            $app->content_like(qr/Dashboard/);
        };
    };

    subtest 'have configured device', sub {
        subtest 'valid password without security token' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            $app->post_ok({
                username => $totp_user->name,
                password => $password,
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };

        subtest 'valid password with valid security token' => sub {
            insert_failedlogin($totp_user);

            local $fixed_time = $totp_when;
            $app->post_ok({
                username       => $totp_user->name,
                password       => $password,
                mfa_totp_token => $totp_valid_token,
            });
            $app->content_like(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 0);
        };

        subtest 'invalid password with valid security token' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            local $fixed_time = $totp_when;
            $app->post_ok({
                username       => $totp_user->name,
                password       => 'Invalid - ' . $password,
                mfa_totp_token => $totp_valid_token,
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };

        subtest 'valid password with invalid security token' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            local $fixed_time = $totp_when;
            $app->post_ok({
                username       => $totp_user->name,
                password       => $password,
                mfa_totp_token => $totp_invalid_token,
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };

        subtest 'valid password with valid recovery code' => sub {
            insert_failedlogin($totp_user);
            my $recovery_codes = initialize_recovery_codes($totp_user) or die $totp_user->errstr;

            $app->post_ok({
                    username       => $totp_user->name,
                    password       => $password,
                    mfa_totp_token => $recovery_codes->[0],
                },
                'Should be able to sign in with valid recovery code'
            );
            $app->content_like(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 0);

            $app->post_ok({
                    username       => $totp_user->name,
                    password       => $password,
                    mfa_totp_token => $recovery_codes->[0],
                },
                'Should not be able to use the same recovery code twice'
            );
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);

            $app->post_ok({
                    username       => $totp_user->name,
                    password       => $password,
                    mfa_totp_token => $recovery_codes->[1],
                },
                'Should be able to sign in with valid recovery code'
            );
            $app->content_like(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 0);
        };

        subtest 'invalid password with valid recovery code' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            my $recovery_codes = initialize_recovery_codes($totp_user) or die $totp_user->errstr;

            $app->post_ok({
                username       => $totp_user->name,
                password       => 'Invalid - ' . $password,
                mfa_totp_token => $recovery_codes->[0],
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };

        subtest 'valid password with invalid recovery code' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            my $recovery_codes = initialize_recovery_codes($totp_user) or die $totp_user->errstr;

            $app->post_ok({
                username       => $totp_user->name,
                password       => $password,
                mfa_totp_token => 'llll-llll',
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };

        subtest 'invalid password with invalid recovery code' => sub {
            MT->model('failedlogin')->remove({ author_id => $totp_user->id });
            my $recovery_codes = initialize_recovery_codes($totp_user) or die $totp_user->errstr;

            $app->post_ok({
                username       => $totp_user->name,
                password       => 'Invalid - ' . $password,
                mfa_totp_token => 'llll-llll',
            });
            $app->content_unlike(qr/Dashboard/);
            is(MT->model('failedlogin')->count({ author_id => $totp_user->id }), 1);
        };
    };
};

subtest '__mode=mfa_login_form' => sub {
    subtest 'does not have a configured device' => sub {
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode   => 'mfa_login_form',
            username => $user->name,
            password => $password,
        });
        is_deeply($app->json, { "error" => undef, "result" => {} });
    };

    subtest 'have a configured device' => sub {
        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->post_ok({
            __mode   => 'mfa_login_form',
            username => $totp_user->name,
            password => $password,
        });
        ok !$app->json->{error};
        like $app->json->{result}{html}, qr/name="mfa_totp_token"/;
    };
};

done_testing();
