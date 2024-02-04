# spf -- expand and report on a given domain's SPF policy

The syntax for the Sender Policy Framework (SPF)
definition via a DNS TXT record is complex and
expansion and inspection of the final ruleset requires
possibly multiple DNS lookups.

The `spf` utility can be used to easily expand a
domain's policy and report on its definition from the
command-line.

For a longer discussion of SPF, please see this blog
post:
https://www.netmeister.org/blog/spf.html

Sample output of the tool (trimmed for brevity):

```
$ spf github.com
github.com:
  policy:
    ip4:192.30.252.0/22 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com include:spf.protection.outlook.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ip4:167.89.101.2 ip4:167.89.101.192/28 ip4:192.254.112.60 ip4:192.254.112.98/31 ip4:192.254.113.10 ip4:192.254.113.101 ip4:192.254.114.176 ip4:62.253.227.114 ~all

  valid

  pass:
    include (7 domains):
      _netblocks.google.com
      _netblocks2.google.com
      _netblocks3.google.com
      _spf.salesforce.com
[...]

    ip4 (12 CIDRs / 1051 IPs):
      166.78.69.169/32
      166.78.69.170/32
      166.78.71.131/32
[...]

    _netblocks.google.com:
      policy:
        ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all

      valid

      pass:
        ip4 (11 CIDRs / 215296 IPs):
          108.177.8.0/21
          173.194.0.0/16
[...]
SPF record for domain 'github.com': valid

Total counts:
  Total # of DNS lookups            : 9

  pass:
    Total # of 'exists' directives  : 1
    Total # of 'include' directives : 8
    Total # of ip4 directives       : 50
    Total # of ip4 addresses        : 870748
    Total # of ip6 directives       : 15
    Total # of ip6 addresses        : 2.97129033104116e+28

All others: softfail
```

Requirements
============

`spf(1)` is written in Perl, and you will need
the following modules installed:

* Net::DNS
* Net::Netmask

Optional modules:

* Data::Dumper
* JSON
* Math::BigInt

You may be able to install these dependencies via:

* NetBSD and other systems using [pkgsrc](https://pkgsrc.org):
`sudo pkg_add p5-JSON p5-Net-DNS p5-Net-Netmask p5-Math-BigInt`
or
`sudo pkgin install p5-JSON p5-Net-DNS p5-Net-Netmask p5-Math-BigInt`
* Debian, Ubuntu, and related systems:
`sudo apt install libjson-perl libnet-dns-perl libnet-netmask-perl libmath-bigint-perl`
* FreeBSD:
`sudo pkg install p5-JSON p5-Net-DNS p5-Net-Netmask p5-Math-BigInt`

You can also find a
[Dockerfile](https://github.com/jschauma/spf/blob/main/misc/Dockerfile)
in the 'misc' directory, if that's your jam.

Installation
============

To install the command and manual page somewhere
convenient, run `make install`; the Makefile defaults
to '/usr/local' but you can change the PREFIX:

```
$ make PREFIX=~ install
```

Documentation
=============

Please see the manual page for all details:


```
NAME
     spf - report on the given domain's use of SPF

SYNOPSIS
     spf [-Vbhjv] [-f format] [-p policy] [-r address] domain

DESCRIPTION
     The spf tool allows you to inspect the Sender Policy Framework DNS records
     for the given domain.

OPTIONS
     The following options are supported by spf:

     -V		 Print version information and exit.

     -b          support large numbers

     -f format   output format (json, perl, text)

     -h		 Display help and exit.

     -j		 Generate output in json format.

     -p policy	 Expand and report on the given policy.	 Note: policy needs to
		 be quoted; see EXAMPLES.

     -r address	 Explicitly query this resolver.

     -v		 Be verbose.  Can be specified multiple times.

DETAILS
     The Sender Policy Framework (SPF) defined in RFC7208 specifies the format
     for the SPF DNS entries a domain may choose to apply.  These entries can
     range from the straight forward to the complex, harboring certain surprises
     or unintenionally obscuring important information, such as when one domain
     includes the SPF records of another domain.

     spf can be used to report on the comprehensive ruleset derived from the DNS
     record.  It does that by counting CIDRs, resolving e.g., MX records, and
     recursively looking up SPF records of any included domains.

EXAMPLES
     The following examples illustrate common usage of this tool.

     To report on the SPF records for the domain netmeister.org:

	   spf netmeister.org

     To query Quad9's public resolver for the same SPF records and report the
     results in json format:

	   spf -r 2620:fe::fe -j netmeister.org

     To expand an arbitrary policy from the command-line:

	   spf -p "v=spf1 a:example.com include:example.net -all"

EXIT STATUS
     The spf utility exits 0 on success, and >0 if an error occurs.

SEE ALSO
     dig(1)

HISTORY
     spf was originally written by Jan Schaumann <jschauma@netmeister.org> in
     July 2022.

BUGS
     Please file bugs and feature requests by emailing the author.
```
