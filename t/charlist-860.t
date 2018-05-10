use Test::More;
use Test::HexString;

use Game::Tibia::Packet::Charlist tibia => 860;

my $instance = Game::Tibia::Packet::Charlist->new;
ok $instance;

done_testing;



