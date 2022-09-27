package MT::Plugin::MFA::TOTP;

use strict;
use warnings;
use utf8;

use MIME::Base64 qw(encode_base64);
use Authen::TOTP;

use MT::Util::Digest::SHA ();

my $RECOVERY_CODE_LENGTH = 8;
my $RECOVERY_CODE_COUNT  = 8;
my %COMMON_TOTP_PARAMS   = (
    algorithm => "SHA512",
);

sub _plugin {
    my $name = __PACKAGE__;
    $name =~ s{\AMT::Plugin::}{};
    $name =~ s{::}{-}g;
    MT->component($name);
}

## _random_bytes and _pseudo_random_bytes copied from MT::Util::UniqueID
sub _random_bytes {
    eval { Crypt::URandom::urandom(40) } || _pseudo_random_bytes();
}

sub _pseudo_random_bytes {
    require Math::Random::MT::Perl;
    require Time::HiRes;
    my $rand = Math::Random::MT::Perl::rand();
    MT::Util::Digest::SHA::sha1($rand . Time::HiRes::time() . $$);
}

## exclude confusing characters 0, o, 1, l from recovery code (32 characters)
my @RECOVERY_CODE_CHARS = split(//, 'abcdefghijkmnpqrstuvwxyz23456789');
sub _generate_recovery_code {
    my $random_bytes = '';
    if (length($random_bytes) < $RECOVERY_CODE_LENGTH * 5 / 8) {
        $random_bytes .= _random_bytes();
    }
    my @chars = map { $RECOVERY_CODE_CHARS[$_] } unpack("%5C" x $RECOVERY_CODE_LENGTH, $random_bytes);

    # aaaabbbb -> aaaa-bbbb
    my @chunks = ();
    while (@chars) {
        push @chunks, join('', splice(@chars, 0, 4));
    }
    return join('-', @chunks);
}

sub _initialize_recovery_codes {
    my ($user) = @_;

    my @codes = map { _generate_recovery_code() } (1 .. $RECOVERY_CODE_COUNT);
    $user->mfa_totp_recovery_codes(join(',', @codes));
}

sub _normalize_token {
    my ($token) = @_;
    return '' unless defined($token);
    $token =~ s/\s+//g;
    $token;
}

sub _is_enabled_for_user {
    my ($user) = @_;
    !!$user->mfa_totp_secret;
}

sub dialog {
    my $app  = shift;
    my $user = $app->user;

    if (_is_enabled_for_user($user)) {
        _plugin()->load_tmpl('disable_dialog.tmpl');
    } else {
        my $tmpl = _plugin()->load_tmpl('enable_dialog.tmpl');

        my $auth = Authen::TOTP->new;
        my $uri  = $auth->generate_otp(
            user   => $user->name,
            issuer => "Movable Type",
            %COMMON_TOTP_PARAMS,
        );
        $app->session->set('mfa_totp_tmp_secret', $auth->secret);

        $tmpl->param({
            plugin_version => _plugin()->version,
            totp_uri       => $uri,
        });
        $tmpl;
    }
}

sub _validate_request {
    my $app = shift;

    if (!$app->validate_magic) {
        $app->{login_again} = 0;
        return;
    }
    return if $app->request_method ne 'POST';

    return 1;
}

sub enable {
    my $app  = shift;
    my $user = $app->user;

    return $app->json_error($app->translate("Invalid request.")) unless _validate_request($app);

    my $secret = $app->session->get('mfa_totp_tmp_secret');
    my $token  = _normalize_token(scalar $app->param('mfa_totp_token'));

    if (_is_enabled_for_user($user) || !$secret) {
        return $app->json_error(_plugin()->translate('Invalid request.'));
    }

    if (!_verify_token($secret, $token)) {
        return $app->json_error(_plugin()->translate('Security token does not match.'));
    }

    $user->mfa_totp_secret($secret);
    _initialize_recovery_codes($user);
    $user->save;
    $app->session->set('mfa_totp_tmp_secret', undef);

    return $app->json_result({
        recovery_codes => [split ',', $user->mfa_totp_recovery_codes],
    });
}

sub _clear_user_totp_secret {
    my ($user) = @_;

    $user->mfa_totp_secret('');
    $user->mfa_totp_recovery_codes('');
    $user->save;
}

sub disable {
    my $app  = shift;
    my $user = $app->user;

    return $app->json_error($app->translate("Invalid request.")) unless _validate_request($app);

    my $token = _normalize_token(scalar $app->param('mfa_totp_token'));

    unless (_verify_token($user->mfa_totp_secret, $token) || _consume_recovery_code($user, $token)) {
        return $app->json_error(_plugin()->translate('Security token does not match.'));
    }

    _clear_user_totp_secret($app->user);

    return $app->json_result({});
}

sub reset_settings {
    my ($cb, $app, $param) = @_;

    _clear_user_totp_secret($param->{user});

    1;
}

sub page_actions {
    my ($cb, $app, $actions) = @_;
    push @$actions, {
        label => _plugin()->translate('Configuring the authentication device'),
        mode  => 'mfa_totp_dialog',
    };
}

sub render_form {
    my ($cb, $app, $param) = @_;

    return 1 if $app->user && !$app->user->mfa_totp_secret;

    push @{ $param->{templates} }, _plugin()->load_tmpl('form.tmpl');
}

sub _verify_token {
    my ($secret, $token) = @_;

    if ($token !~ m/^[0-9]{6}|[0-9]{8}$/) {
        return;
    }

    my $auth = Authen::TOTP->new;
    my $res  = eval {
        $auth->validate_otp(
            secret    => $secret,
            otp       => $token,
            tolerance => 1,
            %COMMON_TOTP_PARAMS,
        );
    };

    MT->log({
        message => $@,
        class   => 'system',
        level   => MT::Log::ERROR(),
    }) if $@;

    return !!$res;
}

sub _consume_recovery_code {
    my ($user, $token) = @_;
    my @codes              = split(',', $user->mfa_totp_recovery_codes);
    my @non_matching_codes = grep { $_ ne $token } @codes;
    if (@codes == @non_matching_codes) {
        # verify failed
        return;
    }

    $user->mfa_totp_recovery_codes(join(',', @non_matching_codes));
    $user->save;

    return 1;
}

sub verify_token {
    my ($cb) = @_;
    my $app  = MT->app;
    my $user = $app->user;

    return 1 unless $user->mfa_totp_secret;

    my $token = _normalize_token(scalar $app->param('mfa_totp_token'));

    return 0 unless _verify_token($user->mfa_totp_secret, $token) || _consume_recovery_code($user, $token);

    return 1;
}

1;
