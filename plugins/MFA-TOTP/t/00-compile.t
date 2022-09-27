use strict;
use warnings;

use FindBin;
use Test::More;

use lib qw(lib extlib), "$FindBin::Bin/../lib", "$FindBin::Bin/../extlib";

use_ok 'MT::Plugin::MFA::TOTP';

done_testing;
