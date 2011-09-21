#!/usr/bin/perl 
use warnings;
use strict;
use FindBin;
use Term::UI;
use Term::ReadLine;
use Data::Dumper;
use Getopt::Long;

my $help        = 0;
my $yes         = 0;
my $full_diff   = 0;
my $auto        = 0;
my $stdin       = 0;
my %opts        = (
    help            => \$help,
    yes             => \$yes,
    diff            => \$full_diff,
    stdin           => \$stdin,
    "no-prompt"     => \$auto,
);

GetOptions( %opts ) or die usage( %opts );
die usage( %opts )  if $help;
die usage( %opts )  unless @ARGV;

my $dir = "$FindBin::Bin/..";
my %map = (
    # to	   from
    production	=> "staging",
    staging	=> "development",
);

my @files;
if( $stdin ) {
    while( <STDIN> ) {
        chomp;
        last unless $_;
        push @files, $_;
    }
}

for my $arg (@ARGV) {

    my $env  = lc($arg) or die usage();
    my $src  = $map{$env} or die "No such env: $env\n" . usage();
    my $from = "$dir/env/$src/";	# trailing slash is critical!
    my $to   = "$dir/env/$env";
    my $term = Term::ReadLine->new('Update Env');
    
    ### you want us to copy over specific files
    if ( $stdin ) {
        print "+++ $_\n" for @files;    

    ### you asked for everything, here's the diff
    ### --binary-files=text is required, or grep will just tell us 
    ### 'binary file matched' if the first file is a binary and
    ### not tell us about anything else
    } else {
        my $diff = qq[diff -Naur $from $to];
        $diff   .= qq[|grep --binary-files=text +++] unless $full_diff;

        system( $diff );
    } 

    my $bool = do {
        local $Term::UI::AUTOREPLY = $auto;
        $term->ask_yn( prompt => "Push to [$env]?", default => $yes );
    };

    if ($bool) {
        
        ### you want us to copy over specific files
        if( $stdin ) {
            for( @files ) {
               
                ### check that the source file makes sense
                unless( m|env/$src| ) {
                    warn "Input file does not match $src: $_";
                    next;
                }

                ### now generate a usable from/to
                my $file      = $_;
                $file         =~ s|.*?env/$src/||g;
                my $from_file = "$dir/env/$src/$file";
                my $to_file   = "$dir/env/$env/$file";

                system( qq[rsync -va $from_file $to_file] ) and die $?;
                system( qq[git add $to_file] ) and die $?;
            }

        ### add all files
        } else {
	    system( qq[rsync -va --delete $from $to] ) and die $?;
	    system( qq[git add $to] ) and die $?;
        }
       
        ### and now commit
	system( qq[git commit $to -m"* automated sync from $src to $env using `git log |head -1`"] ) and die $?;
    }
}

sub usage {
    my %args  = @_;
    my $usage = qq[  
  Usage: $0 ENV [, ENV] [--OPTS]

  Update the environment from its parent. Valid values:
  
  staging     # updates from development
  production  # updates from staging

    \n];
    
    for my $key ( sort keys %args ) {
        $usage .= sprintf( "    %-15s # Default: %s\n", $key, ${$args{$key}} );
    }
    return $usage;
}

