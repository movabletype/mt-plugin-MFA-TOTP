package MT::Plugin::MFA::TOTP;

use strict;
use warnings;
use utf8;

use Authen::TOTP;

use MT::Plugin::MFA::TOTP::Util qw(
    generate_base32_secret initialize_recovery_codes consume_recovery_code
);
use MT::Plugin::MFA::TOTP::Error;
use MT::Util qw(encode_url);
use MT::Util::Digest::SHA ();

my $HASH_ALGORITHM = 'SHA1';

sub _plugin {
    my $name = __PACKAGE__;
    $name =~ s{\AMT::Plugin::}{};
    $name =~ s{::}{-}g;
    MT->component($name);
}

sub _handle_error {
    my ($err) = @_;
    if (eval { $err->isa('MT::Plugin::MFA::TOTP::Error') }) {
        return "$err";
    } else {
        require MT::Util::Log;
        MT::Util::Log::init();
        MT::Util::Log->error($err);
        return MT->translate("An error occurred.");
    }
}

sub _normalize_token {
    my ($token) = @_;
    return '' unless defined($token);
    $token =~ s/\s+//g;
    $token;
}

sub _is_enabled_for_user {
    my ($user) = @_;
    $user->mfa_totp_base32_secret ? 1 : ();
}

sub dialog {
    my $app  = shift;
    my $user = $app->user;

    if (_is_enabled_for_user($user)) {
        _plugin()->load_tmpl('disable_dialog.tmpl');
    } else {
        my $auth   = Authen::TOTP->new;
        my $secret = generate_base32_secret($HASH_ALGORITHM);
        my $digits = _plugin()->get_config_value('totp_digits');
        my $uri    = $auth->generate_otp(
            digits       => $digits,
            base32secret => $secret,
            user         => encode_url($user->name),
            issuer       => encode_url('Movable Type'),
            algorithm    => $HASH_ALGORITHM,
        );
        $app->session->set('mfa_totp_tmp_base32_secret', $secret);

        my $tmpl = _plugin()->load_tmpl('enable_dialog.tmpl', {
            plugin_version => _plugin()->version,
            totp_uri       => $uri,
            totp_digits    => $digits,
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

    my $secret = $app->session->get('mfa_totp_tmp_base32_secret');
    my $token  = _normalize_token(scalar $app->param('mfa_totp_token'));

    if (_is_enabled_for_user($user) || !$secret) {
        return $app->json_error(_plugin()->translate('Invalid request.'));
    }

    if (!_verify_totp_token($secret, $token)) {
        return $app->json_error(_plugin()->translate('Security token does not match.'));
    }

    $app->session->set('mfa_totp_tmp_base32_secret', undef);

    my $recovery_codes;
    eval {
        $user->mfa_totp_base32_secret($secret);
        $user->save or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);
        $recovery_codes = initialize_recovery_codes(
            $user,
            _plugin()->get_config_value('recovery_code_length'),
            _plugin()->get_config_value('recovery_code_count'));
    };

    return $@ ? $app->json_error(_handle_error($@)) : $app->json_result({
        recovery_codes => $recovery_codes,
    });
}

sub _clear_user_totp_data {
    my ($user) = @_;

    $user->mfa_totp_base32_secret('');
    $user->mfa_totp_recovery_codes([]);
    $user->save;
}

sub disable {
    my $app  = shift;
    my $user = $app->user;

    return $app->json_error($app->translate("Invalid request.")) unless _validate_request($app);

    my $token = _normalize_token(scalar $app->param('mfa_totp_token'));

    eval {
        (_verify_totp_token($user->mfa_totp_base32_secret, $token) || consume_recovery_code($user, $token))
            or die MT::Plugin::MFA::TOTP::Error->new(_plugin()->translate('Security token does not match.'));
        _clear_user_totp_data($user)
            or die MT::Plugin::MFA::TOTP::Error->new($user->errstr);
    };

    return $@ ? $app->json_error(_handle_error($@)) : $app->json_result();
}

sub reset_settings {
    my ($cb, $app, $param) = @_;
    my $user = $param->{user};
    return _clear_user_totp_data($user) || $cb->error($user->errstr);
}

sub page_actions {
    my ($cb, $app, $actions) = @_;

    push @$actions, {
        label => _plugin()->translate('Configuring the authentication device'),
        mode  => 'mfa_totp_dialog',
    };

    1;
}

sub render_form {
    my ($cb, $app, $param) = @_;

    return 1 if $app->user && !$app->user->mfa_totp_base32_secret;

    push @{ $param->{templates} }, _plugin()->load_tmpl('form.tmpl', {
        totp_digits => _plugin()->get_config_value('totp_digits'),
    });

    return 1;
}

sub _verify_totp_token {
    my ($secret, $token) = @_;

    if ($token !~ m/^[0-9]{6}|[0-9]{8}$/) {
        return;
    }

    my $auth = Authen::TOTP->new;
    my $res  = eval {
        $auth->validate_otp(
            digits       => _plugin()->get_config_value('totp_digits'),
            tolerance    => _plugin()->get_config_value('totp_tolerance'),
            base32secret => $secret,
            otp          => $token,
            algorithm    => $HASH_ALGORITHM,
        );
    };

    if (my $err = $@) {
        require MT::Util::Log;
        MT::Util::Log::init();
        MT::Util::Log->error($err);
    }

    return $res ? 1 : ();
}

sub verify_token {
    my $app  = MT->app;
    my $user = $app->user;

    return 1 unless $user->mfa_totp_base32_secret;

    my $token = _normalize_token(scalar $app->param('mfa_totp_token'));

    return 1 if _verify_totp_token($user->mfa_totp_base32_secret, $token);

    return eval { consume_recovery_code($user, $token) };
}

1;
