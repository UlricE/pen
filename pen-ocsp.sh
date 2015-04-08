#!/bin/sh

# Run from cron like so:
# 0 * * * * /usr/local/bin/pen-ocsp.sh >> /var/log/pen-ocsp.log 2>&1

CFG=/etc/pen
SNI=$CFG/sni
CTL=/var/run/pen/https.ctl

# get_ocsp cert cacert outfile
get_ocsp()
{
	uri=`openssl x509 -noout -ocsp_uri -in $1`
	if test -z "$uri"; then
		echo "No OCSP URI found in cert"
	else
		host=`echo "$uri"|cut -f 3 -d /`
		openssl ocsp -noverify -issuer "$2" -cert "$1" -url "$uri" -header Host "$host" -respout "$3"
	fi
}

# get_ocsp_default cert cacert outfile
get_ocsp_default()
{
	get_ocsp "$1" "$2" "$3"
	# For the default ssl context, tell Pen to reload the ocsp response.
	penctl "$CTL" "ssl_ocsp_response $3"
}

# get_ocsp_sni domain
get_ocsp_sni()
{
	get_ocsp $SNI/$1.crt $SNI/$1.ca $SNI/$1.ocsp
	# Pen will reload automatically
}

# Sample requests:

# Get OCSP response for default context
get_ocsp_default /etc/pen/mycert.pem /etc/pen/cacert.crt /etc/pen/mycert.ocsp

# Get OCSP response for SNI context
get_ocsp_sni www.example.com



