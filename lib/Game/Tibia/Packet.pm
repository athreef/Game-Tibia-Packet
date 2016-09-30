use strict;
use warnings;
package Game::Tibia::Packet;

# ABSTRACT: Minimal session layer support for the MMORPG Tibia
# VERSION

use Digest::Adler32 qw(adler32);
use Crypt::XTEA;

# XXX workaround for Crypt::XTEA's errornous definitions
# Fix is pushed to Github and awaits author's release
# https://github.com/JaHIY/Crypt-XTEA/issues/3
no warnings 'redefine';
no warnings 'prototype';
*Crypt::XTEA::keysize = sub { 16 };
*Crypt::XTEA::blocksize = sub { 8 };
use strict;
use warnings;
use Crypt::ECB;

=pod

=encoding utf8

=head1 NAME

Game::Tibia::Packet - Session layer support for the MMORPG Tibia

=head1 SYNOPSIS

    use Game::Tibia::Packet;

    # decrypt Tibia packet
    my $read; my $ret = $sock->recv($read, 1024);
    my $res = Game::Tibia::Packet->new($read, $xtea_key);
    $packet_type = unpack('C', $res->payload);


    # encrypt a Tibia speech packet
    my $p = Game::Tibia::Packet->new;
    $p->payload .= pack("C S S S/A S C SSC S/A",
        0xAA, 0x1, 0x0, "Perl", 0, 1, 1, 1, 8,
        "Game::Tibia::Packet says Hi!\n:-)");
    $sock->send($p->finalize($xtea_key}))

=begin HTML

<p><img src="http://athreef.github.io/Game-Tibia-Packet/img/hi.png" alt="Screenshot"></p>

=end HTML


=head1 DESCRIPTION

Methods for constructing Tibia packets. Doesn't handle the XTEA key exchange yet, only what comes after it. i.e. It doesn't do that much besides calculating Adler32 digest and XTEA encryption.

Tested working with Tibia 8.6, but will probably work with later protocol versions too.

=head1 METHODS AND ARGUMENTS

=over 4

=item new([$payload, $xtea])

Constructs a new Game::Tibia::Packet instance. If payload and XTEA are given, the payload will be decrypted and trimmed to correct size. 

=cut

sub new {
	my $type = shift;
	my $self = {
        payload => shift || '',
        xtea => shift,
    };
    if ($self->{payload} ne '')
    {
        #return undef unless isValid($self->{payload});
        my $ecb = Crypt::ECB->new(
            -cipher => Crypt::XTEA->new($self->{xtea}, 32, little_endian => 1)
        );
        $ecb->padding('null');
 
        $self->{payload} = $ecb->decrypt(substr($self->{payload}, 6));
        $self->{payload} = substr $self->{payload}, 2, unpack('v', $self->{payload});
    }

	%{$self->{FLAGS}} = 
	(
		XTEA => 1,
		ADLER32 => 1,
		RSA => 0,
		VER => 8.72,
	);

	bless $self, $type;
	return $self;
}

=item isValid($packet)

Checks if packet's adler32 digest matches (A totally unnecessary thing on Cipsoft's part, as we already have TCP checksum. Why hash again?) 

=cut

sub isValid {
	my $packet = shift;

	my ($len, $adler) = unpack('(S a4)<', $packet);
	return 0 if $len + 2 != length $packet;

	my $a32 = Digest::Adler32->new;
	$a32->add(substr($packet, 6));
	return 0 if $a32->digest ne reverse $adler;
	1;
	#TODO: set errno to checksum failed or length doesnt match
}

=item payload() : lvalue

returns the payload as lvalue (so you can concat on it)

=cut

sub payload : lvalue {
	my $self = shift;
    return $self->{payload};
}

=item finalize([$XTEA_KEY])

Finalizes the packet. XTEA encrypts, prepends checksum and length.

=cut


sub finalize {
	my $self = shift;
    my $XTEA = $self->{xtea} // shift;

	my $packet = $self->{payload};
	if ($self->{FLAGS}{XTEA} and defined $XTEA) {
		$packet = CORE::pack('v', length $packet) . $packet;
        
        my $ecb = Crypt::ECB->new(
            -cipher => Crypt::XTEA->new($XTEA, 32, little_endian => 1)
        );
        $ecb->padding('null');
 
        $packet = $ecb->encrypt($packet);
    }

	my $digest = '';
	if ($self->{FLAGS}{ADLER32}) {
		my $a32 = Digest::Adler32->new;
		$a32->add($packet);
		$digest = reverse $a32->digest;
	}

	$packet = CORE::pack("S/a", $digest.$packet);

	$packet;
}


1;
__END__

=back

=head1 GIT REPOSITORY

L<http://github.com/athreef/Game-Tibia-Packet>

=head1 SEE ALSO

The protocol was reverse engineered as part of writing my L<Tibia Wireshark Plugin|https://github.com/a3f/Tibia-Wireshark-Plugin>.

L<http://tpforums.org/forum/forum.php>
L<http://tibia.com>

=head1 AUTHOR

Ahmad Fatoum C<< <athreef@cpan.org> >>, L<http://a3f.at>

=head1 DISCLAIMER

Tibia is copyrighted by Cipsoft GmbH.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 Ahmad Fatoum

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
