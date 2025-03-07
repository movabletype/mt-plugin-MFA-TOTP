use strict;
use warnings;
use utf8;

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

my $app    = MT::Test::App->new('MT::App::CMS');
my $plugin = MT->component('MFA-TOTP');

subtest 'totp_issuer' => sub {
    subtest 'update with valid value' => sub {
        my $issuer = 'Example-CMS powered by Movable Type';
        ok $plugin->save_config({ totp_issuer => $issuer }, 'system');
        is $plugin->get_config_value('totp_issuer'), $issuer;
    };

    subtest 'update with valid max length value' => sub {
        my $issuer = 'a' x 40;
        ok $plugin->save_config({ totp_issuer => $issuer }, 'system');
        is $plugin->get_config_value('totp_issuer'), $issuer;
    };

    subtest 'update with valid value wrapped with spaces' => sub {
        my $issuer = 'Example-CMS powered by Movable Type';
        ok $plugin->save_config({ totp_issuer => "   $issuer   " }, 'system');
        is $plugin->get_config_value('totp_issuer'), $issuer, 'saved value is trimmed';
    };

    my @invalid_issuers = (
        '',
        'a' x 51,
        '@invalid issuer',
        'CMS!',
        'シックス・アパート',
    );
    for my $issuer (@invalid_issuers) {
        subtest "update with invalid value: $issuer" => sub {
            ok !$plugin->save_config({ totp_issuer => $issuer }, 'system');
            isnt $plugin->get_config_value('totp_issuer'), $issuer;
        };
    }
};

done_testing();
