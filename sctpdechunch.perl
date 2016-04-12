#! /usr/bin/perl -w

use strict;
use Data::Dumper;

sub error ($$) {
  my ($pkt, $str) = @_;

  print STDERR Dumper ($pkt);
  print STDERR "ignoring packet $pkt->{n} - $str\n";
  print "packet $pkt->{n} - ignoring - $str\n";
  die "\n";
}

my ($fin, $fout);

sub read_pcap {
  my ($buf);

  read $fin, $buf, 24 or die;
  my @gh = unpack 'LSSlLLL', $buf;

  $gh[0] == 0xa1b2c3d4 or die "bad magic $gh[0] not a pcap?";
  $gh[6] == 1 or die "bad link type $gh[6]";

  my $num;
  while (1) {
    $num++;
    read $fin, $buf, 16 or last;
    my @rh = unpack 'LLLL', $buf;
    $rh[2] == $rh[3] or die "packet $num truncated\n";
    read ($fin, $buf, $rh[2]) == $rh[2] or die "packet $num read: $!";
    eval {
      parse_eth ({ n => $num, ts_sec => $rh[0],
        ts_usec => $rh[1], len => $rh[2] }, $buf);
    };
    die $@ if $@;
  }
}

sub parse_eth {
  my ($pkt, $data) = @_;
  $pkt->{eth} = \my %eth;

  @eth{qw/ dst src type data /} = unpack 'H12H12na*', $data;

  if ($eth{type} == 0x0800) {
    parse_ip ($pkt, $eth{data});
  } elsif ($eth{type} == 0x8100) {
    parse_dot1q ($pkt, $eth{data});
  } else {
    error $pkt, "eth unknown type $eth{type}";
  }
}

sub parse_dot1q {
  my ($pkt, $data) = @_;

  $pkt->{dot1q} = \my %dot1q;
  @dot1q{qw/ vlan type data /} = unpack 'nna*', $data;
  if ($dot1q{type} == 0x0800) {
    $pkt->{eth}{type} = 0x0800; # fix
    parse_ip ($pkt, $dot1q{data});
  } else {
    error $pkt, "dot1q unknown type $dot1q{type}";
  }
}

sub parse_ip {
  my ($pkt, $data) = @_;

  $pkt->{ip} = \my %ip;

  $ip{len} = unpack 'x2n', $data;
  ($data, $ip{pad}) = unpack "a$ip{len} a*", $data;
  @ip{qw/ hlen tos len id foffset ttl proto cksum src
    dst data /} = unpack 'CCnnnCCna4a4a*', $data;

  error $pkt, "bad ip" if $ip{hlen} != 0x45;
  
  $ip{flags} = $ip{foffset} >> 13;
  $ip{offset} = $ip{foffset} & 0x1fff;
  error $pkt, "ip fragmented" if ($ip{flags} & 1) || $ip{offset};

  if ($ip{proto} == 0x84) {
    parse_sctp ($pkt, $ip{data});
  }
}

sub parse_sctp {
  my ($pkt, $data) = @_;

  $pkt->{sctp} = \my %sctp;

  @sctp{qw/ src_port dst_port sctp_verif chksum chunks /} =
    unpack "nnNNa*", $data;

  while (length $sctp{chunks}) {
    @sctp{qw/ type flags len chunks /} =
      unpack 'CCna*', $sctp{chunks};
    @sctp{qw/ value chunks /} =
      unpack 'a' . ($sctp{len}-4) .'x![N] a*', $sctp{chunks};

    put_pkt ($pkt) if $sctp{type} == 0; # DATA only
  }
}

sub put_hdr {
  print $fout pack 'LSSlLLL', 0xa1b2c3d4, 2, 4, 0, 0, 0, 1;
}

my $init_crc32 = oct reverse sprintf "%032bb0", 0x1EDC6F41; # 0x04C11DB7;
my @crc32 = map {
  for my $s (0..7) {
    $_ = $_ >> 1 ^ ($_ & 1 && $init_crc32)
  }
  $_
} 0..255;

sub crc32 {
  my ($data) = @_;

  my $crc = 0xffffffff;
  for (unpack 'C*', $data) {
    $crc = $crc >> 8 ^ $crc32[$crc & 0xff ^ $_];
  }
  return pack 'V', $crc ^ 0xffffffff;
}

crc32 ("mtve") eq pack 'H*', '90583b2e'
  or die "Broken crc32";

sub put_pkt {
  my ($pkt) = @_;

  my $chunk = pack 'CCna' . ($pkt->{sctp}{len}-4) . 'x![N]',
    @{ $pkt->{sctp} }{qw/ type flags len value/};
  my $sctp = pack 'nn NNa*', @{ $pkt->{sctp} }{qw/ src_port dst_port
    sctp_verif /}, 0, $chunk;
  $sctp |= "\0" x 8 . crc32 ($sctp);
  my $ip = pack 'CCnn nCCna4a4a*', @{ $pkt->{ip} }{qw/ hlen tos len id
    foffset ttl proto cksum src dst /}, $sctp;
  my $eth = pack 'H12H12na*', @{ $pkt->{eth} }{qw/ dst src type /}, $ip;

  print $fout pack 'LLLLa*', @$pkt{qw/ ts_sec ts_usec /},
    length $eth, length $eth, $eth;
}

open $fin, '<', $ARGV[0] or die "open $ARGV[0]: $!";
binmode $fin;

open $fout, '>', $ARGV[1] or die "create $ARGV[1]: $!";
binmode $fout;

put_hdr ();
read_pcap ();
