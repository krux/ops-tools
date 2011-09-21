#!/usr/bin/perl
use strict;
use warnings;
use File::Basename qw[basename];

BEGIN {
    use FindBin;
    chdir $FindBin::Bin;
}

my $name = pop or die usage();
my $type = shift() || "components";
my $root = "$FindBin::Bin/../env/development";
my $tdir = "$root/$type";
my $path = "$tdir/$name";

my %layout = (
    files	=> [ qw|.exists| ],
    manifests   => [ qw|init.pp params.pp| ],
    templates   => [ ],
);

die "No such directory '$tdir'" unless -d $tdir;

print "Setting up files under $path...";

### set up the base directories
while ( my($dir, $fref) = each %layout ) {
    system( "mkdir -p $path/$dir" ) and die $?;

    for my $file ( @$fref ) {
        system( "touch $path/$dir/$file" ) and die $?;
    }
}

print "done\n";

sub usage {
    my $me = basename( $0 );
    return qq[
$me [TYPE] NAME

Example:

    $me services s_mysql  # new service for mysql servers
    $me kmysql            # new component

    \n];
}
