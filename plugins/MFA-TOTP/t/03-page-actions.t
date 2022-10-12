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
use MT::Test::App;

$test_env->prepare_fixture('db');

my $user = MT::Author->load(1);
my $app  = MT::Test::App->new('MT::App::CMS');

my $totp_base32_secret = '12345678901234567890';

subtest '__mode=mfa_page_actions' => sub {
    $app->login($user);

    subtest 'does not have a configured device' => sub {
        $user->mfa_totp_base32_secret(undef);
        $user->save or die $user->errstr;

        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->get_ok({
            __mode => 'mfa_page_actions',
        });
        is scalar(@{ $app->json->{result}{page_actions} }), 1;
        is $app->json->{result}{page_actions}[0]{mode}, 'mfa_totp_dialog';
    };

    subtest 'have a configured device' => sub {
        $user->mfa_totp_base32_secret($totp_base32_secret);
        $user->save or die $user->errstr;

        local $ENV{HTTP_X_REQUESTED_WITH} = 'XMLHttpRequest';
        $app->get_ok({
            __mode => 'mfa_page_actions',
        });
        is scalar(@{ $app->json->{result}{page_actions} }), 2;
        is $app->json->{result}{page_actions}[0]{mode}, 'mfa_totp_manage_recovery_codes';
        is $app->json->{result}{page_actions}[1]{mode}, 'mfa_totp_dialog';
    };
};

done_testing();
