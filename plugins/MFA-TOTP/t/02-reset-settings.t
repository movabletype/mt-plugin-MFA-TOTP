use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../extlib", "$FindBin::Bin/../../../t/lib";

use Test::More;
use MT::Test::Env;

use MT::Plugin::MFA::TOTP::Util qw(initialize_recovery_codes);

our $test_env;
BEGIN {
    $test_env = MT::Test::Env->new;
    $ENV{MT_CONFIG} = $test_env->config_file;
}

use MT::Test;
use MT::Test::Permission;
use MT::Test::App;

$test_env->prepare_fixture('db');

my $admin = MT::Author->load(1);
my $app   = MT::Test::App->new('MT::App::CMS');

subtest '__mode=mfa_reset' => sub {
    $app->login($admin);

    my $totp_user = MT::Test::Permission->make_author;
    $totp_user->mfa_totp_base32_secret('1234567890123456789012345678901234567890123456789012345678901234');
    $totp_user->save                      or die $totp_user->errstr;
    initialize_recovery_codes($totp_user) or die $totp_user->errstr;

    $app->post_ok({
        __mode       => 'mfa_reset',
        _type        => 'author',
        return_args  => '__mode=list&blog_id=0&_type=author',
        all_selected => 1,
    });
    $totp_user->refresh;
    ok !$totp_user->mfa_totp_base32_secret, 'should remove a secret';
    ok !@{$totp_user->mfa_totp_recovery_codes || []}, 'should remove recovery codes';
    like $app->last_location, qr/\?__mode=list&blog_id=0&_type=author&saved_status=mfa_reset/, "saved_status is mfa_reset";
};

done_testing();
