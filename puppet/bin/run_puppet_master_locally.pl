#!/usr/bin/perl
use strict;
use warnings;
use File::Basename qw[dirname basename];
use File::Spec;
use FindBin;

my $default_port     = 8140;
my $port             = shift or die "Need port\n" . usage();
my $my_dir           = File::Spec->rel2abs( $FindBin::Bin );
my $confdir          = File::Spec->catdir( $my_dir, '..' );
my $puppet_conf      = '/etc/puppet/puppet.conf';
my $my_puppet_conf   = "/tmp/puppet.conf.$port";
my @opts             = @ARGV;

if( $port == $default_port ) {
  die "Can't run on default port $default_port\n" . usage();
}

print << ".";
**************************************************
Note: be sure to set: 

  'puppet_master_port': '$port' 

in the node classifier configuration for the node
you intend to be developing on/against. 
**************************************************

.

### Since we start using Foreman, we can't use just $confdir anymore, 
### as Foreman can't expand it from the puppet conf and gets confused.
### Big Big Sigh. See: http://xrl.us/ForemanPuppetConfdir,
###
### So instead, we take /etc/puppet/puppet.conf, but do a search/replace
### on it and use that as the configuration instead. Fun isn't it?
###
### Only run it if the puppet configuration got updated in the meantime
if( (stat($puppet_conf))[9] > ((stat($my_puppet_conf))[9] || 0) ) {
    print "\n*** Fixing up puppet configuration\n\n";

    open my $in_fh,       $puppet_conf    or die "Can not open $puppet_conf: $!";
    open my $out_fh, '>', $my_puppet_conf or die "Can not open $my_puppet_conf: $!";

    while( <$in_fh> ) {
        s|/etc/puppet|\$confdir|g;
        print $out_fh $_;
    }
}

my @cmd = ( qw[sudo puppet master --no-daemonize --verbose --debug], 
            qw[--masterport], $port, qw[--config ], $my_puppet_conf,
            qw[--pidfile], "/tmp/puppetmaster.$port.pid", 
            qw[--confdir ], $confdir, @opts );

print "Running: @cmd\n\n";
system( @cmd ) and die $?;

sub usage {
  my $me = basename($0);
  return qq[
Usage: $me PORT [PUPPET_MASTER_OPTS]
  \n\n];
}

