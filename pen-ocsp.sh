#!/bin/sh

# Run from cron like so:
# 0 * * * * /usr/local/bin/pen-ocsp.sh >> /var/log/pen-ocsp.log 2>&1

# Suggested file hierarchy:
# /etc/pen	# General configuration files
# /etc/pen/sni	# Private keys, certificates et al, including default certificate
# /etc/pen/sni/example.com.key	# Private key for example.com
# /etc/pen/sni/example.com.crt	# Certificate for example.com
# /etc/pen/sni/example.com.ca	# CA's certificate for example.com
# /etc/pen/sni/example.com.ocsp	# OCSP response file, auto-loaded by this script
# /etc/pen/sni/example.net.key	# Private key for example.net
# /etc/pen/sni/example.net.crt	# Certificate for example.net
# /etc/pen/sni/example.net.ca	# CA's certificate for example.net
# /etc/pen/sni/example.net.ocsp	# OCSP response file, auto-loaded by this script

# Pen *requires* a default certificate in order to enable SSL. It is suggested that
# this certificate is placed in /etc/pen/sni with the other certificates.

CFG=/etc/pen
SNI=$CFG/sni
CTL=/var/run/pen/https.ctl

# Sample domains, default domain first:
DOMAINS="example.com example.net"

# No changes should be necessary below this line.


# get_ocsp cert cacert outfile
get_ocsp()
{
	uri=`openssl x509 -noout -ocsp_uri -in $1`
	if test -z "$uri"; then
		echo "No OCSP URI found in cert"
	else
		host=`echo "$uri"|cut -f 3 -d /`
		openssl ocsp -noverify -issuer "$2" -cert "$1" -url "$uri" -header Host "$host" -respout "$3.tmp"
		if test -s "$3.tmp"; then
			mv "$3.tmp" "$3"
		else
			echo "No response for $1"
		fi
	fi
}

for d in $DOMAINS; do
	get_ocsp $SNI/$d.crt $SNI/$d.ca $SNI/$d.ocsp
done

# Tell Pen to reload the ocsp response for the default ssl context.
set $DOMAINS
if test -s "$SNI/$1.ocsp"; then
	penctl "$CTL" "ssl_ocsp_response" "$SNI/$1.ocsp"
else
	echo "No response for default domain $1"
fi

