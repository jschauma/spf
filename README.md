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

Requirements
============

`spf(1)` is written in Perl, and you will need
the following modules installed:

* JSON
* Net::DNS
* Net::Netmask

On Debian and related systems, you may be able to
install these dependencies with:

`sudo apt install libjson-perl libnet-dns-perl libnet-netmask-perl`

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
```
NAME
     spf - report on the given domain's use of SPF

SYNOPSIS
     spf [-Vhjv] [-p policy] [-r address] domain

DESCRIPTION
     The spf tool allows you to inspect the Sender Policy Framework DNS records
     for the given domain.

OPTIONS
     The following options are supported by spf:

     -V		 Print version information and exit.

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
