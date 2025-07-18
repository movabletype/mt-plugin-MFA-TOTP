use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../../../t/lib";

use Test::More;
use MT::Test::Env;

our $test_env;
BEGIN {
    $test_env = MT::Test::Env->new;
    $ENV{MT_CONFIG} = $test_env->config_file;
}

use MT::Test;
use MT::Test::Permission;
use MT::Test::App;

$test_env->prepare_fixture('db');

my $password = 'password';
my $user     = MT::Author->load(1);
$user->set_password($password);
$user->save or die $user->errstr;

my $app = MT::Test::App->new(
    app_class   => 'MT::App::CMS',
    no_redirect => 1,
);
my $plugin = MT->component('MFA');
$plugin->set_config_value('mfa_enforcement', 1);

subtest 'mfa_enforcement: true' => sub {
    subtest "Sign in as a user who has no configured MFA" => sub {
        subtest 'allowed methods' => sub {
            for my $mode (qw(mfa_totp_dialog mfa_totp_generate_recovery_codes mfa_totp_enable)) {
                subtest "GET $mode" => sub {
                    $app->get_ok({
                        __mode   => $mode,
                        username => $user->name,
                        password => $password,
                    });
                    ok !$app->{locations};
                };
            }
        };

        subtest 'not allowed methods' => sub {
            for my $mode (qw(mfa_totp_disable)) {
                local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
                subtest "GET $mode" => sub {
                    $app->get({
                        __mode   => $mode,
                        username => $user->name,
                        password => $password,
                    });
                    $app->status_is(401);
                    ok $app->json->{error};
                };
            }
            for my $mode (qw(mfa_totp_manage_recovery_codes)) {
                subtest "GET $mode" => sub {
                    $app->get_ok({
                        __mode   => $mode,
                        username => $user->name,
                        password => $password,
                    });
                    like $app->last_location, qr/__mode=mfa_requires_settings/;
                };
            }
        };
    };
};

done_testing();
