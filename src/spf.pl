#! /usr/local/bin/perl -Tw
#
# This tool can expand and report on the given domains SPF use.
# This is accomplished by (possibly recursive) inspection of the DNS
# TXT records in question.
#
# Originally written in July 2022 by Jan Schaumann <jschauma@netmeister.org>.

use 5.008;

use strict;
use File::Basename;
use Getopt::Long;
Getopt::Long::Configure("bundling");

use JSON;

use Socket qw(PF_INET PF_INET6 inet_ntoa inet_pton);

use Net::DNS;
use Net::Netmask;


###
### Constants
###

use constant TRUE => 1;
use constant FALSE => 0;

use constant EXIT_FAILURE => 1;
use constant EXIT_SUCCESS => 0;

use constant MAXLOOKUPS => 10;

# RFC7208, Section 3.4
use constant MAXLENGTH => 450;

###
### Globals
###

my %OPTS = ( v => 0 );
my $PROGNAME = basename($0);
my $RETVAL = 0;
my $VERSION = 0.2;

# The final result in json representation:
# {
#   "query"    : "input domain",
#   "expanded" : {
#     "<domain>": {
#       "all"     : mechanism,
#       "errors"  : [ error, error, ...],
#       "spf"     : "SPF record for the domain",
#       "parents  : [ domain, domain, ...],
#       "pass"    : {
#         "a"       : {
#           "cidrs"   : [ cidr, cidr, ...],
#           "names"   : [ name, name, ...],
#           "ips"     : [ IP, IP, IP, ... ],
#         },
#         "cidrs"   : {
#             "ip4"      : [ ipv4-cidr, ... ],
#             "ip6"      : [ ipv6-cidr, ... ],
#         },
#         "count"   : {
#           "a-names"  : count-of-a-names,
#           "a-ips"    : count-of-a-ips,
#           "exists"   : count-of-exists,
#           "exp"      : count-of-exp,
#           "include"  : count-of-includes,
#           "ip4count" : count-of-all-v4-ips,
#           "ip4cidrs" : count-of-v4-cidrs,
#           "ip6count" : count-of-all-v6-ips,
#           "ip6cidrs" : count-of-v6-cidrs,
#           "mx-names" : count-of-mx-names,
#           "mx-ips"   : count-of-mx-ips,
#           "ptr"      : count-of-ptrs,
#         },
#         "exists"  : [ domain-spec, domain-spec, ...],
#         "exp"     : [ domain-spec, domain-spec, ...],
#         "include" : [ domain, domain, ... ],
#         "ip4"     : [ IP, IP, IP, ... ],
#         "ip6"     : [ IP, IP, IP, ... ],
#         "mx"      : {
#           "cidrs"   : [ cidr, cidr, ...],
#           "names"   : [ mx, mx, ...],
#           "ips"     : [ IP, IP, IP, ... ],
#         },
#         "ptr"     : [ domain, domain, ...],
#         "redirect": domain,
#       },
#       "neutral" : {
#         as above
#       }
#       "softfail": {
#         as above
#       }
#       "fail"    : {
#         as above
#       }
#       "valid"   : valid|invalid
#       "warnings": [ warning, warning, ...],
#     },
#     "<domain2>" : {
#       for each include/redirect, a full object as for 'domain' above
#     },
#     "total" : {
#       "pass" : {
#         "exists"   : count-of-exists,
#         "exp"      : count-of-exp,
#         "include"  : count-of-includes,
#         "ip4cidrs" : count-of-v4-cidrs,
#         "ip4count" : count of all IPs,
#         "ip6cidrs" : count-of-v6-cidrs,
#         "ip6count" : count of all IPs,
#         "ptr"      : count-of-ptr,
#         "redirect" : count-of-redirect,
#      },
#      repeat for other qualifiers
#   }
# }
my %RESULT;

# This is super-yanky: the RFC says there shouldn't be more than 10
# *additional* lookups, i.e., not including the initial first TXT
# record lookup.  So instead of setting our MAX to 11 or some other
# shenanigans, we'll start with -1 instead.
$RESULT{"lookups"} = -1;

###
### Subroutines
###

sub addIPCounts($$$) {
	my ($domain, $q, $aref) = @_;
	my @ips = @{$aref};

	my @v4 = grep(!/:/, @ips);
	$RESULT{"expanded"}{$domain}{$q}{"count"}{"ip4count"} += scalar(@v4);

	my @v6 = grep(/:/, @ips);
	$RESULT{"expanded"}{$domain}{$q}{"count"}{"ip6count"} += scalar(@v6);
}

sub addTopCountsByQualifier($);
sub addTopCountsByQualifier($) {
	my ($domain) = @_;
	verbose("Adding up top counts by qualifier for query '$domain'...", 1);

	if (!defined($RESULT{"expanded"}{$domain})) {
		return;
	}

	my %domainData = %{$RESULT{"expanded"}{$domain}};
	if (defined($domainData{"redirect"})) {
		my $d = $domainData{"redirect"};
		verbose("Encountered redirect...", 2);
		if (defined($RESULT{"redirect"}{$d})) {
			warning("Redirect loop - already redirected through '$d'!");
			return;
		}

		$RESULT{"redirect"}{$d} = 1;
		addTopCountsByQualifier($d);
		return;
	}

	foreach my $q (qw/fail neutral pass softfail/) {
		if (!defined($domainData{$q})) {
			next;
		}

		if (!defined($domainData{$q}{"count"})) {
			next;
		}

		my %counts = %{$domainData{$q}{"count"}};

		foreach my $k (keys(%counts)) {
			$RESULT{"total"}{$q}{$k} += $counts{$k};
		}
	}
}

sub addTotals($$$) {
	my ($parent, $q, $dom) = @_;

	verbose("Adding up '$q' totals for included domain '$dom' to '$parent'...", 2);

	if (defined($RESULT{"expanded"}{$dom}{"warnings"})) {
		push(@{$RESULT{"expanded"}{$parent}{"warnings"}},
				@{$RESULT{"expanded"}{$dom}{"warnings"}});
	}

	# If an invalid included policy encounters an error, it returns an error
	if ($RESULT{"expanded"}{$dom}{"valid"} eq "invalid") {
		$RESULT{"expanded"}{$parent}{"valid"} = "invalid";
		my @errors;
		if (defined($RESULT{"expanded"}{$parent}{"errors"})) {
			my (@errors, %e);
			%e = map { $_ => 1 } @{$RESULT{"expanded"}{$parent}{"errors"}};
			@errors = keys(%e);
		}
		if (defined($RESULT{"expanded"}{$dom}{"errors"})) {
			push(@errors, @{$RESULT{"expanded"}{$dom}{"errors"}});
			$RESULT{"expanded"}{$parent}{"errors"} = \@errors;
		}
		# ...but we still want to count results, so we continue.
	}

	if (!defined($RESULT{"expanded"}{$parent}{$q}{"count"})) {
		return;
	}

	# Only explicit "pass" from the domain are added.
	my %count = %{$RESULT{"expanded"}{$parent}{$q}{"count"}};

	if (!defined($RESULT{"expanded"}{$dom}{"pass"}{"count"})) {
		# No "pass", so nothing to add.
		return;
	}

	my %childCount = %{$RESULT{"expanded"}{$dom}{"pass"}{"count"}};

	foreach my $which (qw/exists exp include ip4count ip4cidrs ip6count ip6cidrs/) {
		if (defined($childCount{$which})) {
			$count{$which} += $childCount{$which};
		}
	}
	foreach my $which (qw/a mx/) {
		if (defined($childCount{"${which}-names"})) {
			$count{"${which}-names"} += $childCount{"${which}-names"};
		}
	}
	$RESULT{"expanded"}{$parent}{$q}{"count"} = \%count;
}

sub error($;$) {
	my ($msg, $err) = @_;

	warning($msg, "Error");

	$RETVAL++;
	if ($err) {
		exit($err);
		# NOTREACHED
	}
}

# XXX: verify individual IPs are not in other subnets? Seems expensive...
sub expandAorMX($$$$$$) {
	my ($res, $domain, $q, $which, $sep, $spec) = @_;

	verbose("Expanding $which for domain '$domain'...", 2);
	$RESULT{"expanded"}{$domain}{$q}{"count"}{"${which}-names"}++;

	my $cidr = "";
	my ($v4cidr, $v6cidr);
	($spec, $v4cidr, $v6cidr) = parseAMX($domain, $sep, $spec);
	if (!$spec) {
		return FALSE;
	}

	my (%result, %names, %ipaddrs);

	if (defined($RESULT{"expanded"}{$domain}{$q}{$which})) {
       		%result = %{$RESULT{"expanded"}{$domain}{$q}{$which}};
		%names = map { $_ => 1 } @{$result{"names"}};

		if ($result{"ips"}) {
			%ipaddrs = map { $_ => 1 } @{$result{"ips"}};
		}
	}

	if ($spec =~ m/%/) {
		# RFC7208, Section 7 allows for macros;
		# we can't resolve those, so don't bother trying
		verbose("Not resolving '$spec' - macro expansion required.", 2);
	} else {
		if ($which eq "a") {
			$names{$spec} = 1;
			foreach my $ip (getIPs($res, $spec)) {
				$ipaddrs{$ip} = 1;
			}

		} elsif ($which eq "mx") {
			incrementLookups("mx", $spec);

			my @mxs = mx($res, $spec);
			if (!scalar(@mxs)) {
				spfError("No MX record for domain '$spec' found.", $domain, "warn");
				# "TRUE" because the entry was well formatted.
				return TRUE;
			}

			if (scalar(@mxs) > 10) {
				# RFC7208, Section 4.6.4
				spfError("More than 10 MX records for domain '$spec' found.", $domain);
				return TRUE;
			}

			foreach my $rr (@mxs) {
				my $mx = $rr->exchange;
				$names{$mx} = 1;
				foreach my $ip (getIPs($res, $mx)) {
					$ipaddrs{$ip} = 1;
				}
			}
		}
	}

	my @names = keys(%names);
	$RESULT{"expanded"}{$domain}{$q}{$which}{"names"} = \@names;

	my @iparray = keys(%ipaddrs);
	if ($v4cidr || $v6cidr) {
		my $ips = expandAMXCIDR($domain, $q, "a", \@iparray, $v4cidr, $v6cidr);
		if (!$ips) {
			return TRUE;
		}
		$RESULT{"expanded"}{$domain}{$q}{$which}{"cidrs"} = \@{$ips};
		$RESULT{"expanded"}{$domain}{$q}{"count"}{"${which}-cidrs"} = scalar(@{$ips});
	} else {
		$RESULT{"expanded"}{$domain}{$q}{$which}{"ips"} = \@iparray;
		$RESULT{"expanded"}{$domain}{$q}{"count"}{"${which}-ips"} += scalar(@iparray);

		addIPCounts($domain, $q, \@iparray);
	}

	return TRUE;
}

sub expandAMXCIDR($$$$$$) {
	my ($domain, $q, $which, $aref, $v4cidr, $v6cidr) = @_;

	if (!$v4cidr) {
		$v4cidr = 32;
	}
	if (!$v6cidr) {
		$v6cidr = 128;
	}

	my @ips;
	my $cidr = $v4cidr;
	foreach my $ip (@{$aref}) {
		if (inet_pton(PF_INET, $ip)) {
			push(@ips, "$ip/$v4cidr");
		} elsif (inet_pton(PF_INET6, $ip)) {
			push(@ips, "$ip/$v6cidr");
			$cidr = $v6cidr;
		} else {
			spfError("Invalid IP address $ip for '$domain'.", $domain);
			next;
		}
	}

	$RESULT{"expanded"}{$domain}{$q}{"count"}{"${which}-cidrs"} = scalar(@ips);
	foreach my $c (@ips) {
		my $count = getCidrCount($c, $domain);
		if ($count < 0) {
			spfError("Invalid $which mechanism '${which}/${cidr}' for domain '$domain' found.", $domain);
			return undef;
		}
		if ($c =~ m/:/) {
			$RESULT{"expanded"}{$domain}{$q}{"count"}{"ip6count"} += $count;
		} else {
			$RESULT{"expanded"}{$domain}{$q}{"count"}{"ip4count"} += $count;
		}
	}

	return \@ips;
}

sub expandCIDR($$$$) {
	my ($qualifier, $domain, $ipv, $cidr) = @_;

	if (!$cidr) {
		spfError("Invalid definition '$ipv:' for domain '$domain'.", $domain);
		return;
	}

	verbose("Expanding CIDR $ipv:$cidr for domain '$domain'...", 2);
	$RESULT{"expanded"}{$domain}{$qualifier}{"count"}{"${ipv}cidrs"}++;

	if ($cidr !~ m/\/[0-9]+$/) {
		if (!inet_pton(PF_INET, $cidr) && !inet_pton(PF_INET6, $cidr)) {
			spfError("Invalid IP '$cidr' for domain '$domain' found.", $domain);
			return;
		}
		if ($cidr =~ m/:/) {
			$cidr .= "/128";
		} else {
			$cidr .= "/32";
		}
	}

	my $count = getCidrCount($cidr, $domain);
	if ($count < 0) {
		spfError("Invalid CIDR '$cidr' for domain '$domain' found.", $domain);
		return;
	}

	my (%c, @cidrs);
	if (defined($RESULT{"expanded"}{$domain}{$qualifier}{"cidrs"}{$ipv})) {
       		@cidrs = @{$RESULT{"expanded"}{$domain}{$qualifier}{"cidrs"}{$ipv}};
		%c = map { $_ => 1 } @cidrs;
	}

	$c{$cidr} = 1;
	@cidrs = keys(%c);
       	$RESULT{"expanded"}{$domain}{$qualifier}{"cidrs"}{$ipv} = \@cidrs;

	my $s = $count;
	if (defined($RESULT{"expanded"}{$domain}{$qualifier}{"count"}{"${ipv}count"})) {
		$s += $RESULT{"expanded"}{$domain}{$qualifier}{"count"}{"${ipv}count"};
	}

	if ($s > 0) {
		$RESULT{"expanded"}{$domain}{$qualifier}{"count"}{"${ipv}count"} = $s;
	}
}

sub expandGeneric($$$$) {
	my ($which, $domain, $qualifier, $dest) = @_;

	verbose("Expanding '$which' for domain '$domain'...", 2);
	$RESULT{"expanded"}{$domain}{$qualifier}{"count"}{$which}++;

	my (@list, %hash);
	if (defined($RESULT{"expanded"}{$domain}{$qualifier}{$which})) {
       		@list = @{$RESULT{"expanded"}{$domain}{$qualifier}{$which}};
		%hash = map { $_ => 1 } @list;
	}

	$hash{$dest} = 1;

	@list = keys(%hash);
       	$RESULT{"expanded"}{$domain}{$qualifier}{$which} = \@list;
}

sub expandSPF($$$$);
sub expandSPF($$$$) {
	my ($res, $qualifier, $domain, $parent) = @_;
	verbose("Expanding SPF for '$domain' ($qualifier)...", 1);

	my %parents;
	if (defined($RESULT{"expanded"}{$domain}{"parents"})) {
		%parents = map { $_ => 1 } @{$RESULT{"expanded"}{$domain}{"parents"}};
		if ($parents{$parent}) {
			spfError("Recursive inclusion of '$domain'.", $domain);
			return;
		} elsif (defined($RESULT{"expanded"}{$domain})) {
			verbose("Already seen $domain.", 2);
			return;
		}
	}

	$parents{$domain} = 1;
	my @a = keys(%parents);
	$RESULT{"expanded"}{$domain}{"parents"} = \@a;

	my $spfText = getSPFText($res, $domain);
	if (!$spfText) {
		$RESULT{"expanded"}{$domain}{"valid"} = "invalid";
		return;
	}

	$RESULT{"expanded"}{$domain}{"valid"} = "valid";
	$RESULT{"expanded"}{$domain}{"spf"} = $spfText;
	$RESULT{"expanded"}{$domain}{"all"} = "neutral (implicit)";

	my @directives = split(/ /, $spfText);
	my $n = 0;
	foreach my $entry (@directives) {
		verbose("Encountered '$entry' directive...", 2);
		my $q = $qualifier;
		$n++;
		if ($entry =~ m/^([+?~-])?(a|mx)(([:\/])(.*))?$/i) {
			if ($1) {
				$q = getQualifier($1);
			}
			my $which = $2;
			my $sep = $4;
			my $arg = $5;
			if (!expandAorMX($res, $domain, $q, $which, $sep, $arg)) {
				spfError("Invalid directive '$entry' for $domain.", $domain);
			}
		}
		elsif ($entry =~ m/^([+?~-])?all$/i) {
			if ($1) {
				$q = getQualifier($1);
			}

			$RESULT{"expanded"}{$domain}{"all"} = $q;
			if ($n != scalar(@directives) && ($directives[$n] !~ m/^exp=/)) {
				spfError("'all' directive is not last in '$domain' policy - ignoring all subsequent directives.", $domain, "warn");
				# RFC7208, Section 5.1:
				# Mechanisms after "all" will never be tested.
				# Mechanisms listed after "all" MUST be ignored.
				last;
			}
		}
		elsif ($entry =~ m/^([+?~-])?(ip[46]):(.*)$/i) {
			if ($1) {
				$q = getQualifier($1);
			}
			expandCIDR($q, $domain, $2, $3);
		}
		elsif ($entry =~ m/^([+?~-])?(include:|redirect=)(.*)$/i) {
			# "redirect" should not have a qualifier, but allowing it
			# here makes our regex easier
			if ($1) {
				$q = getQualifier($1);
			}
			my $type = $2;
			my $dom = $3;
			chop($type);

			if ($type eq "include") {
				$RESULT{"expanded"}{$domain}{$q}{"count"}{$type}++;
				push(@{$RESULT{"expanded"}{$domain}{$q}{$type}}, $dom);
			} else {
				if ($spfText =~ m/\b[+?~-]?all\b/) {
					spfError("Ignored 'redirect=$dom' in '$domain' policy with 'all' statement", $domain, "warn");
					next;
				}
				$RESULT{"expanded"}{$domain}{"redirect"} = $dom;
			}

			expandSPF($res, $q, $dom, $domain);
			addTotals($domain, $q, $dom);

			if ($type eq "redirect") {
				$RESULT{"expanded"}{$domain}{"all"} = $RESULT{"expanded"}{$dom}{"all"};
			}

		}
		elsif ($entry =~ m/^([+?~-])?(exists:|ptr:?|exp=)(.*)$/i) {
			if ($1) {
				$q = getQualifier($1);
			}
			my $type = $2;
			chop($type);

			# Both exists and ptr have a lookup...
			if ($type ne "exp") {
				incrementLookups($type, $3);
			}

			# But ptr also leads to forward lookups, one for every
			# PTR record returned (and there may be many!), so we
			# add at least one more here.
			if ($type eq "ptr") {
				incrementLookups($type, $3);
			}
			expandGeneric($type, $domain, $q, $3);
		} elsif ($entry) {
			spfError("Unknown directive '$entry' for '$domain'.", $domain);
		}
	}

	if (defined($RESULT{"expanded"}{$domain}{"errors"})) {
		$RESULT{"expanded"}{$domain}{"valid"} = "invalid";
	}
}


sub getCidrCount($$) {
	my ($cidr, $domain) = @_;

	# Net::Netmask doesn't handle IPv4-mapped addresses.
	if ($cidr =~ m/::ffff:[0-9.]+(\/([0-9]+))/) {
		my $nm = $2;
		if (!$nm) {
			# Assume /128
			return 1;
		} else {
			my $n = 128 - $nm;
			return (2**$n);
		}
	}

	my $block = Net::Netmask->new2(lc($cidr));
	if (!$block) {
		return -1;
	}

	my $count = $block->size();
	if ($cidr =~ m/:/) {
		$count = $count->numify();
	}

	return $count;
}

sub getIPs($$) {
	my ($res, $domain) = @_;

	verbose("Looking up all IPs for '$domain'...", 3);

	my (%ips, %tmp);
	my $req;

	# We only do one increment here even though we perform two lookups
	# because when the mail server performs the lookup, it will only
	# perform a single lookup based on whether the client connected over
	# IPv4 or IPv6.
	incrementLookups("a/aaaa", $domain);

	foreach my $a (qw/A AAAA/) {
		$req = $res->send($domain, $a);
		if (!defined($req)) {
			error($res->errorstring);
		}

		foreach my $rr (grep($_->type eq $a, $req->answer)) {
			$ips{$rr->rdstring} = 1;
		}
	}

	return keys(%ips);
}

sub getQualifier($) {
	my ($q) = @_;

	my $qualifier = "pass";
	if ($q) {
		if ($q eq "?") {
			$qualifier = "neutral";
		} elsif ($q eq "~") {
			$qualifier = "softfail";
		} elsif ($q eq "-") {
			$qualifier = "fail";
		}
	}

	return $qualifier;
}
	
sub getSPFText($$) {
	my ($res, $domain) = @_;

	verbose("Looking up SPF records for domain '$domain'...", 1);

	if ($domain =~ m/%/) {
		# RFC7208, Section 7 allows for macros;
		# we can't resolve those, so don't bother trying
		verbose("Ignoring '$domain' - macro expansion required.", 2);
		return;
	}

	incrementLookups("txt", $domain);

	my $req = $res->send($domain, "TXT");
	if (!defined($req)) {
		error($res->errorstring);
		return;
	}

	if ($req->header->ancount < 1) {
		my $errmsg = "No TXT record found for '$domain'.";
		if ($res->errorstring ne "NOERROR") {
			$errmsg = "Unable to look up TXT record for '$domain'; nameserver returned " . $res->errorstring . ".";
		}
		if ($domain eq $RESULT{"query"}) {
			error($errmsg, EXIT_FAILURE);
			# NOTREACHED
		}
		spfError($errmsg, $domain, "warn");
		return;
	}

	my $spf;
	foreach my $rr ($req->answer) {
		my $s = $rr->rdstring;
		$s =~ s/"//g;
		$s =~ s/[	\n"]//gi;

		if ($s =~ m/^"?v=spf1 (.*)/si) {
			my $l = length($s);
			if ($l > MAXLENGTH) {
				spfError("SPF record for '$domain' too long ($l > " . MAXLENGTH . ").", $domain, "warn");
			}
			$spf = $1;
		}
	}

	if (!$spf) {
		my $errmsg = "No SPF record found for '$domain'.";;
		if ($domain eq $RESULT{"query"}) {
			error($errmsg, EXIT_FAILURE);
			# NOTREACHED
		}
		spfError($errmsg, $domain, "warn");
		return;
	}

	$spf =~ s/[\n"]//gi;
	$spf =~ s/\s+/ /g;

	return $spf;
}

sub incrementLookups($$) {
	my ($rr, $d) = @_;

	verbose("DNS lookup of type '$rr' for $d...", 3);

	$RESULT{"lookups"}++;
}

sub init() {
	my ($ok);

	if (!scalar(@ARGV)) {
		error("I have nothing to do.  Try -h.", EXIT_FAILURE);
		# NOTREACHED
	}

	$ok = GetOptions(
			 "expand|e" 	=> \$OPTS{'e'},
			 "help|h" 	=> \$OPTS{'h'},
			 "json|j" 	=> \$OPTS{'j'},
			 "resolver|r=s"	=> \$OPTS{'r'},
			 "verbose|v+" 	=> sub { $OPTS{'v'}++; },
			 "version|V"	=> sub {
			 			print "$PROGNAME: $VERSION\n";
						exit(EXIT_SUCCESS);
			 		}
			 );

	# We can untaint the given resolver; this is GIGO.
	if ($OPTS{'r'} && $OPTS{'r'} =~ m/(.*)/) {
		$OPTS{'r'} = $1;
	}

	if ($OPTS{'h'} || !$ok) {
		usage($ok);
		exit(!$ok);
		# NOTREACHED
	}

	if (scalar(@ARGV) != 1) {
		error("Please specify exactly one domain.", EXIT_FAILURE);
		# NOTREACHED
	}

	$OPTS{'domain'} = $ARGV[0];
}

sub main() {
	my $domain = $OPTS{'domain'};
	$RESULT{"query"} = $domain;

	my %resolver_opts;
       
	if ($OPTS{'v'} > 3) {
		$resolver_opts{'debug'} = 1;
	}

	if ($OPTS{'r'}) {
		$resolver_opts{'nameservers'} = [ $OPTS{'r'} ];
	}

	my $res = Net::DNS::Resolver->new(%resolver_opts);
	expandSPF($res, "pass", $domain, "top");

	my $n = $RESULT{"lookups"};
	if ($n > MAXLOOKUPS) {
		my $err = "Too many DNS lookups ($n > " . MAXLOOKUPS . ").";
		spfError($err, $domain);
	}
}


sub parseAMX($$$) {
	my ($domain, $sep, $spec) = @_;

	# Possible mechanisms for a and mx (by example of mx):
	# mx -- use $domain
	if (!defined($spec)) {
		# invalid: "mx:" or "mx/"
		if (defined($sep)) {
			return (undef, undef, undef);
		}
		$spec = $domain;
		return ($spec, undef, undef);
	}

	# mx:dom/4cidr//6cidr -- use $dom, then add cidr to each IP
	# mx:dom//6cidr -- use $dom, then add cidr to each IP
	# mx:dom/4cidr -- use $dom, then add cidr to each IP
	# mx:dom -- use $dom, no cidr
	if (($sep eq ":") && ($spec =~ m/^([^\/]+)(\/([0-9]+))?(\/\/([0-9]+))?$/)) {
		my $dom = $1;
		my $v4 = $3;
		my $v6 = $5;
		if (($v4 && $v4 > 32) || ($v6 && $v6 > 128)) {
			return (undef, undef, undef);
		}
		return ($dom, $v4, $v6);
	}

	if ($sep eq "/") {
		# mx//6cidr
		if ($spec =~ m/^\/([0-9]+)$/) {
			return ($domain, undef, $1);
		}
		# mx/4cidr//6cidr
		# mx/4cidr
		if ($spec =~ m/^([0-9]+)(\/\/([0-9]+))?$/) {
			return ($domain, $1, $3);
		}
	}

	# everything else is a syntax error
	return (undef, undef, undef);
}

sub printAMXStat($$$$) {
	my ($space, $which, $type, $aref) = @_;
	my @array = @{$aref};

	my $n = scalar(@array);
	if ($n < 1) {
		return;
	}

	printf("%s%s (%s %s%s):\n", $space, $which, $n, $type, $n > 1 ? "s" : "");
	print "$space  " . join("\n$space  ", sort(@array)) . "\n";
	print "\n";
}

sub printArray($$$) {
	my ($name, $aref, $indent) = @_;

	if (!defined($aref)) {
		return;
	}

	my $n = scalar(@{$aref});
	my $space = "  " x ($indent + 1);
	printf("%s%s (%s domain%s):\n", $space, $name, $n,
			$n > 1 ? "s" : "");
	print "$space  " . join("\n$space  ", sort(@{$aref})) . "\n";
	print "\n";
}

sub printExpanded($$);
sub printExpanded($$) {
	my ($domain, $indent) = @_;

	if (!defined($RESULT{"expanded"}{$domain})) {
		return;
	}

	if (defined($RESULT{"seen"}{$domain})) {
		return;
	}

	$RESULT{"seen"}{$domain} = 1;

	if (!defined($RESULT{"expanded"}{$domain}{"spf"})) {
		# e.g., a macro domain
		return;
	}

	print "  " x ($indent - 1);
	print "$domain:\n";
	print "  " x $indent;
	print "policy:\n";
	print "  " x ($indent + 1);
	print $RESULT{"expanded"}{$domain}{"spf"} . "\n";
	print "\n";

	print "  " x $indent;
	print $RESULT{"expanded"}{$domain}{"valid"} . "\n";
	printWarningsAndErrors($indent, $domain);

	my $space = "  " x $indent;
	if (defined($RESULT{"expanded"}{$domain}{"redirect"})) {
		my $r = $RESULT{"expanded"}{$domain}{"redirect"};
		print "${space}redirect: $r\n";
		print "\n";
		printExpanded($r, $indent + 2);
		print "\n";
	}

	$space = "  " x ($indent + 1);

	foreach my $qual (qw/pass neutral softfail fail/) {
		my $i = $RESULT{"expanded"}{$domain}{$qual};
		if (!defined($i) || !scalar(keys(%{$i}))) {
			next;
		}
		my %info = %{$i};

		print "  " x $indent;
		print "$qual:\n";

		foreach my $i (qw/exists exp include ptr/) {
			printArray($i, $info{$i}, $indent);
		}

		if (defined($info{"cidrs"})) {
			my %cidrs = %{$info{"cidrs"}};
			foreach my $ipv (qw/ip4 ip6/) {
				if (defined($cidrs{$ipv})) {
					my @cidrs = @{$cidrs{$ipv}};
					my $cnum = scalar(@cidrs);
					my $inum = $info{"count"}{"${ipv}count"};
					printf("%s%s (%s CIDR%s / %s IP%s):\n",
							$space, $ipv, $cnum,
							$cnum > 1 ? "s" : "",
							$inum,
							$inum > 1 ? "s" : "");

					# Yes, sort() isn't quite right for CIDRs,
					# but good enough.
					print "$space  " . join("\n$space  ", 
							sort(@cidrs)) . "\n";
					if (($ipv eq "ip4") && (defined($cidrs{"ip6"}))) {
						print "\n";
					}
				}
			}
			print "\n";
		}

		foreach my $m (qw/a mx/) {
			if (defined($info{$m})) {
				my (%h, @n, @i, @c);
				my ($nnum, $inum, $cnum) = (0, 0, 0);

				%h = %{$info{$m}};
				@n = @{$h{"names"}};
				$nnum = scalar(@n);
				printAMXStat($space, $m, "name", \@n);

				if (defined($h{"ips"})) {
					@i = @{$h{"ips"}};
					$inum = scalar(@i);
					printAMXStat($space, $m, "IP", \@i);
				}
				if (defined($h{"cidrs"})) {
					@c = @{$h{"cidrs"}};
					$cnum = scalar(@c);
					printAMXStat($space, $m, "CIDR", \@c);
				}
			}
		}

		foreach my $i (@{$info{"include"}}) {
			if ($RESULT{"expanded"}{$i}{"valid"} eq "valid") {
				printExpanded($i, $indent + 2);
				print "\n";
			}
		}
	}

	print "  " x $indent;
	print "All others: " . $RESULT{"expanded"}{$domain}{"all"} . "\n";
}

sub printCount($$) {
	my ($href, $indent) = @_;

	if (!defined($href)) {
		return;
	}

	my %stats = %{$href};

	foreach my $s (qw/exists exp include ptr redirect/) {
		if (defined($stats{$s})) {
			print "  " x ($indent + 1);
			printf("Total # of %s directives%s: ", $s, " " x (length("redirect") - length($s)));
			print $stats{$s} . "\n";
		}
	}

	foreach my $s (qw/a mx/) {
		if (defined($stats{"${s}-names"})) {
			print "  " x ($indent + 1);
			printf("Total # of %s directives%s: ", $s, " " x (length("redirect") - length($s)));
			print $stats{"${s}-names"} . "\n";
		}
	}

	foreach my $ipv (qw/ip4 ip6/) {
		if (defined($stats{"${ipv}cidrs"})) {
			print "  " x ($indent + 1);
			print "Total # of $ipv CIDRs          : ";
			print $stats{"${ipv}cidrs"} . "\n";
		}
		if (defined($stats{"${ipv}count"})) {
			print "  " x ($indent + 1);
			print "Total # of $ipv addresses      : ";
			print $stats{"${ipv}count"} . "\n";
		}
	}

	print "\n";
}

sub printResults() {
	my $domain = $RESULT{"query"};

	if (!defined($RESULT{"expanded"}{$domain})) {
		return;
	}

	addTopCountsByQualifier($domain);

	printExpanded($domain, 1);

	print "\n";
	print "SPF record for domain '$domain': " . $RESULT{"expanded"}{$domain}{"valid"} . "\n";
	printWarningsAndErrors(0, $domain);

	print "Total counts:\n";
	print "  Total number of DNS lookups     : " . $RESULT{"lookups"} . "\n\n";

	foreach my $qual (qw/pass neutral softfail fail/) {
		if (!defined($RESULT{"total"}{$qual})) {
			next;
		}

		my %stats = %{$RESULT{"total"}{$qual}};
		if (!scalar(keys(%stats)) > 0) {
			next;
		}

		print "  $qual:\n";
		printCount(\%stats, 1);
	}
	print "All others: " . $RESULT{"expanded"}{$domain}{"all"} . "\n";
}

sub printWarningsAndErrors($$) {
	my ($indent, $domain) = @_;
	if (defined($RESULT{"expanded"}{$domain}{"warnings"})) {
		my $s = "  " x ($indent + 1) . "Warning: ";
		print "$s" . join("\n$s", @{$RESULT{"expanded"}{$domain}{"warnings"}}) . "\n";
	}
	if (defined($RESULT{"expanded"}{$domain}{"errors"})) {
		my $s = "  " x ($indent + 1) . "Error: ";
		print "$s" . join("\n$s", @{$RESULT{"expanded"}{$domain}{"errors"}}) . "\n";
	}
	print "\n";
}

sub spfError($$;$) {
	my ($msg, $domain, $warn) = @_;

	if (!$warn) {
		push(@{$RESULT{"expanded"}{$domain}{"errors"}}, $msg);
		$RESULT{"expanded"}{$domain}{"valid"} = "invalid";
	} else {
		push(@{$RESULT{"expanded"}{$domain}{"warnings"}}, $msg);
	}
}

sub usage($) {
	my ($err) = @_;

	my $FH = $err ? \*STDERR : \*STDOUT;

	print $FH <<EOH
Usage: $PROGNAME [-Vhjv] [-r address] domain
        -V          print version information and exit
	-h          print this help and exit
	-j          print output in json format
	-r address  explicitly query this resolver
	-v          increase verbosity
EOH
	;
}

sub verbose($;$) {
	my ($msg, $level) = @_;
	my $char = "=";

	return unless $OPTS{'v'};

	$char .= "=" x ($level ? ($level - 1) : 0 );

	if (!$level || ($level <= $OPTS{'v'})) {
		print STDERR "$char> $msg\n";
	}
}

sub warning($;$) {
	my ($msg, $note) = @_;

	if (!$note) {
		$note = "Warning";
	}

	if (!$OPTS{'q'}) {
		print STDERR "$PROGNAME: $note: $msg\n";
	}
}


###
### Main
###

init();

main();

if ($OPTS{'j'}) {
	my $json = JSON->new;
	print $json->pretty->encode(\%RESULT);
} else {
	printResults();
}

#use Data::Dumper;
#print Data::Dumper::Dumper \%RESULT;

exit($RETVAL);
