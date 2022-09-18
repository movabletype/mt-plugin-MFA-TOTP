package MT::Plugin::MFA::TOTP;

use strict;
use warnings;
use utf8;

use MIME::Base64 qw(encode_base64);
use Authen::TOTP;

use MT::Util::Digest::SHA ();

my %common_totp_params = (
    algorithm => "SHA512",
);

sub plugin {
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

## exclude confusing characters 0, o, 1, l from license code (32 characters)
my @RECOVERY_CODE_CHARS = split(//, 'abcdefghijkmnpqrstuvwxyz23456789');
sub generate_recovery_code {
    my $length       = 8;                                                                         #  Can raise up to 40
    my $random_bytes = _random_bytes();
    my @chars        = map { $RECOVERY_CODE_CHARS[$_] } unpack("%5C" x $length, $random_bytes);
    my @chunks       = ();
    while (@chars) {
        push @chunks, join('', splice(@chars, 0, 4));
    }
    return join('-', @chunks);
}

sub initialize_recovery_codes {
    my ($user) = @_;
    my $count = 8;

    my @codes = map { generate_recovery_code() } (1 .. $count);
    $user->mfa_totp_recovery_codes(join(',', @codes));
}

sub isEnabled {
    !!MT->app->user->mfa_totp_secret;
}

sub dialog {
    my $app = shift;

    if (isEnabled()) {
        plugin()->load_tmpl('disable_dialog.tmpl');
    } else {
        my $tmpl = plugin()->load_tmpl('enable_dialog.tmpl');

        my $auth = Authen::TOTP->new;
        my $uri  = $auth->generate_otp(
            user   => MT->app->user->name,
            issuer => "Movable Type",
            %common_totp_params,
        );
        $app->session->set('mfa_totp_secret', $auth->secret);    # store generated secret temporary

        $tmpl->param({
            plugin_version => plugin()->version,
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

    my $secret = $app->session->get('mfa_totp_secret');
    (my $token = $app->param('mfa_totp_token') || '') =~ s/\s+//g;

    if (!$secret || $user->mfa_totp_secret) {
        return $app->json_error(plugin()->translate('Invalid request.'));
    }

    if (!_verify_token($secret, $token)) {
        return $app->json_error(plugin()->translate('Security token does not match.'));
    }

    $user->mfa_totp_secret($secret);
    initialize_recovery_codes($user);
    $user->save;
    $app->session->set('mfa_totp_secret', undef);

    return $app->json_result({
        recovery_codes => [split ',', $user->mfa_totp_recovery_codes],
    });
}

sub _disable {
    my ($user) = @_;

    $user->mfa_totp_secret('');
    $user->mfa_totp_recovery_codes('');
    $user->save;
}

sub disable {
    my $app  = shift;
    my $user = $app->user;

    return $app->json_error($app->translate("Invalid request.")) unless _validate_request($app);

    (my $token = $app->param('mfa_totp_token') || '') =~ s/\s+//g;

    unless (_verify_token($user->mfa_totp_secret, $token) || _verify_recovery_code($user, $token)) {
        return $app->json_error(plugin()->translate('Security token does not match.'));
    }

    _disable($app->user);

    return $app->json_result({});
}

sub reset_settings {
    my ($cb, $app, $param) = @_;

    _disable($param->{user});

    1;
}

sub page_actions {
    my ($cb, $app, $actions) = @_;
    push @$actions, {
        label => plugin()->translate('Configuring the authentication device'),
        mode  => 'mfa_totp_dialog',
    };
}

sub show_settings {
    my ($cb, $app, $param) = @_;

    my $tmpl = plugin()->load_tmpl('settings.tmpl');
    $tmpl->param({
        enabled => isEnabled(),
    });

    push @{ $param->{templates} }, $tmpl;
}

sub render_form {
    my ($cb, $app, $param) = @_;

    return 1 if $app->user && !$app->user->mfa_totp_secret;

    push @{ $param->{templates} }, plugin()->load_tmpl('form.tmpl');
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
            %common_totp_params,
        );
    };

    MT->log({
        message => $@,
        class   => 'system',
        level   => MT::Log::ERROR(),
    }) if $@;

    return !!$res;
}

sub _verify_recovery_code {
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

    (my $token = $app->param('mfa_totp_token') || '') =~ s/\s+//g;

    return 0 unless _verify_token($user->mfa_totp_secret, $token) || _verify_recovery_code($user, $token);

    return 1;
}

1;
