# MFA-TOTP

This is a plugin for the Movable Type.
This plugin enables multi factor authentication by RFC6238 OTP.

## Installation

1. Install [MFA plugin](https://github.com/movabletype/mt-plugin-MFA) to the MT.
1. Download an archive file from [releases](https://github.com/movabletype/mt-plugin-MFA-TOTP/releases).
1. Unpack an archive file.
1. Upload unpacked files to the MT `plugins` directory.

Should look like this when installed:

    $MT_HOME/
        plugins/
            MFA-TOTP/

## Requirements

* Movable Type 7
* [MFA plugin](https://github.com/movabletype/mt-plugin-MFA)

## Thanks

This plugin includes these cpan modules.

* [Authen::TOTP](https://metacpan.org/pod/Authen::TOTP)
* [MIME::Base32](https://metacpan.org/pod/MIME::Base32)

## LICENSE

Copyright (c) Six Apart Ltd. All Rights Reserved.
