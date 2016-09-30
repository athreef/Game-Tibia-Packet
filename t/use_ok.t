use Test::More tests => 1;
use strict;
use warnings;

BEGIN {
    use_ok 'Game::Tibia::Packet';
}
my $p = Game::Tibia::Packet->new;
