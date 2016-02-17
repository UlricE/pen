#!/bin/sh

# Some assembly required - see bottom of script.

# We need two local ipv4 addresses, these should be available in a virtualbox vm
IP1=127.0.0.1
IP2=10.0.2.15
# Otherwise put them in testsuite.cfg
if test -s ./testsuite.cfg; then
	. ./testsuite.cfg
fi

PID=./autotest.pid
CTL=./autotest.ctl

DIG="dig +short +time=3 +retry=0"

fail()
{
	echo "$1" 1>&2
	exit 1
}

isrunning()
{
	ps -ef|grep -v grep|grep "./pen " > /dev/null 2>&1
}

stop_pen()
{
	# Make sure pen is not running
	killall pen > /dev/null 2>&1
	sleep 1
	if isrunning; then
		fail "Pen is running"
	fi

	# Make sure pid file and control sockets don't exist
	rm -f $PID $CTL
	if test -f $PID; then
		fail "PID file $PID exists"
	fi
	if test -f $CTL; then
		fail "Control socket $CTL exists"
	fi
}

start_pen()
{
	echo "Command line: ./pen -p $PID -C $CTL -X $1"
	./pen -p $PID -C $CTL -X $1
	if ! isrunning; then
		fail "Pen did not start"
	fi
}

penctl()
{
	echo "./penctl $CTL $@"
	./penctl $CTL $@ > /dev/null
}

# Usage: sample host command
sample()
{
	S=`ssh $1 "$2"`
	echo "$S"
}

check_result()
{
	echo "$1: expected '$2', got '$3'"
	if test -z "$3" -o "$2" != "$3"; then
		fail "Wrong result"
	fi
}

check_different()
{
	echo "$1: expected not '$2', got '$3'"
	if test -z "$3" -o "$2" = "$3"; then
		fail "Wrong result"
	fi
}

echo "Test run: `date`"
echo
echo "Testing TCP with IP-based client tracking"
stop_pen
start_pen "8080 127.0.0.1:100 127.0.0.1:101"

# Try fetching the web server hostname
H1a=`curl -s http://$IP1:8080/`
check_different "First result" "" "$H1a"
H1b=`curl -s http://$IP1:8080/`
# We are tracking client IP so expect this to be identical"
check_result "Second result" "$H1a" "$H1b"
# But not this
H2a=`curl -s http://$IP2:8080/`
check_different "Third result" "$H1a" "$H2a"
H2b=`curl -s http://$IP2:8080/`
check_result "Fourth result" "$H2a" "$H2b"
echo "Success"
echo

echo "Testing TCP without client tracking"
stop_pen
start_pen "-r 8080 127.0.0.1:100 127.0.0.1:101"

H1a=`curl -s http://$IP1:8080/`
check_different "First result" "" "$H1a"
H1b=`curl -s http://$IP1:8080/`
check_different "Second result" "$H1a" "$H1b"
H2a=`curl -s http://$IP2:8080/`
check_result "Third result" "$H1a" "$H2a"
H2b=`curl -s http://$IP2:8080/`
check_different "Fourth result" "$H2a" "$H2b"
echo Success
echo

echo "Testing UDP with IP-based client tracking"
stop_pen
start_pen "-U 8080 $IP1:53 $IP2:53"

# Try fetching the web server hostname
H1a=`$DIG @$IP1 -p 8080 example.com`
check_different "First result" "" "$H1a"
# We are tracking client IP so expect this to be identical"
H1b=`$DIG @$IP1 -p 8080 example.com`
check_result "Second result" "$H1a" "$H1b"
# But not this
H2a=`$DIG @$IP2 -p 8080 example.com`
check_different "Third result" "$H1a" "$H2a"
H2b=`$DIG @$IP2 -p 8080 example.com`
check_result "Fourth result" "$H2a" "$H2b"
echo Success
echo

echo "Testing UDP without client tracking"
stop_pen
start_pen "-Ur 8080 $IP1:53 $IP2:53"

# Try fetching the web server hostname
H1a=`$DIG @$IP1 -p 8080 example.com`
check_different "First result" "" "$H1a"
H1b=`$DIG @$IP1 -p 8080 example.com`
check_different "Second result" "$H1a" "$H1b"
H2a=`$DIG @$IP2 -p 8080 example.com`
check_result "Third result" "$H1a" "$H2a"
H2b=`$DIG @$IP2 -p 8080 example.com`
check_different "Fourth result" "$H2b" "$H2a"
echo Success
echo

echo "Testing failover with UDP (see issue #19)"
stop_pen
for p in 10000 10001 10002; do
	./pen -U $p $IP1:53
	H=`$DIG @$IP1 -p $p example.com`
	check_result "Result from target $p" "1.1.1.1" "$H"
done
echo Targets prepared

start_pen "-Ur 5353 127.0.0.1:10000 127.0.0.1:10001 127.0.0.1:10002"
echo Pen started
H=`$DIG @127.0.0.1 -p 5353 example.com`
check_result "First result from load balanced service" "1.1.1.1" "$H"
echo Blacklist one server
penctl server 1 blacklist 30
H=`$DIG @127.0.0.1 -p 5353 example.com`
check_result "Second result from load balanced service" "1.1.1.1" "$H"
echo Blacklist another server
penctl server 2 blacklist 30
H=`$DIG @127.0.0.1 -p 5353 example.com`
check_result "Third result from load balanced service" "1.1.1.1" "$H"
echo Blacklist third server, expecting dig to fail
penctl server 0 blacklist 30
H=`$DIG @127.0.0.1 -p 5353 example.com`
E=$?
echo "dig exit code: $E"
echo "Fourth result: $H"
if test "$E" != "9"; then
	fail "Wrong dig exit code"
fi
echo Whitelist one server
penctl server 0 blacklist 0
H=`$DIG @127.0.0.1 -p 5353 example.com`
check_result "Fifth result from load balanced service" "1.1.1.1" "$H"
echo "Success"
echo

echo "Testing emergency server"
stop_pen
start_pen "-r -e 127.0.0.1:102 10000 127.0.0.1:100 127.0.0.1:101:0:0:101"
# Curl repeatedly to verify that roundrobin works:
H1=`curl -s http://localhost:10000/`
check_different "First result" "" "$H1"
H2=`curl -s http://localhost:10000/`
check_different "Second result" "$H1" "$H2"
echo Blacklist one of the servers so that all replies come from the other server
penctl server 0 blacklist 100
H1=`curl -s http://localhost:10000/`
check_different "Third result" "" "$H1"
H2=`curl -s http://localhost:10000/`
check_result "Fourth result" "$H1" "$H2"
echo Blacklist the other server. Now all replies should come from the emergency server
penctl server 1 blacklist 100
H1=`curl -s http://localhost:10000/`
check_result "Fifth result" "Emergency" "$H1"
echo Whitelist one of the servers
penctl server 0 blacklist 0
H1=`curl -s http://localhost:10000/`
check_different "Sixth result" "" "$H1"
H2=`curl -s http://localhost:10000/`
check_result "Seventh result" "$H1" "$H2"
echo Whitelist the other server
penctl server 1 blacklist 0
H1=`curl -s http://localhost:10000/`
check_different "Eighth result" "" "$H1"
H2=`curl -s http://localhost:10000/`
check_different "Ninth result" "$H1" "$H2"
echo Success
echo

echo "Testing abuse server"
stop_pen
start_pen "-B 127.0.0.1:103 10000 127.0.0.1:100"
penctl acl 1 permit $IP1
penctl client_acl 1
H=`curl -s http://$IP1:10000/`
check_different "First result" "Abuse" "$H"
H=`curl -s http://$IP2:10000/`
check_result "Second result" "Abuse" "$H"
penctl client_acl 0
H=`curl -s http://$IP2:10000/`
check_different "Third result" "Abuse" "$H"
echo "Blocking access to single regular server will result in dropped connection"
penctl server 0 acl 1
H=`curl -s http://$IP1:10000/`
check_different "Fourth result" "Abuse" "$H"
H=`curl -s http://$IP2:10000/`
echo "curl exit code: $?"
echo "Fifth result: expected '', got '$H'"
if test "$H" != ""; then
	fail "Wrong result"
fi
echo Success

echo
echo "Testing SSL termination"
stop_pen
start_pen "-E siag.pem 1443 127.0.0.1:100"
H=`curl -sk https://127.0.0.1:1443/`
check_result "First result" "100" "$H"
echo Success

# Absurdly, glibc requires an IPv6 address on a non-loopback interface
# in order for getaddrinfo to handle IPv6. This can be accomplished thus:
# /sbin/ifconfig eth1 add ::2/128
echo
echo "Testing IPv6 to IPv4 conversion"
stop_pen
start_pen ":::10000 127.0.0.1:100"
H=`curl -sg6 http://[::1]:10000/`
check_result "First result" "100" "$H"
echo Success

echo
echo "Testing IPv4 to IPv6 conversion"
stop_pen
start_pen "127.0.0.1:10000 [::1]:100"
H=`curl -s4 http://127.0.0.1:10000/`
check_result "First result" "100" "$H"
echo Success

echo
echo "Testing signal handling"
stop_pen
echo "server 0 address 127.0.0.1 port 100" > autotest.cfg
start_pen "10000 -F autotest.cfg"
H=`curl -s http://127.0.0.1:10000/`
check_result "First result" "100" "$H"
echo "server 0 address 127.0.0.1 port 101" > autotest.cfg
kill -HUP `cat $PID`
H=`curl -s http://127.0.0.1:10000/`
check_result "Second result" "101" "$H"
echo Success

# The next two tests, transparent reverse proxy and direct server return, require
# extensive setting up. The are therefore conditioned on having separate config
# in testsuite.cfg. It might look something like this (only not commented out):

#TRP_PEN=192.168.1.2
#TRP_BACK1=192.168.2.2
#TRP_BACK2=192.168.2.3
#TRP_MYIP=192.168.1.1

#DSR_PEN=192.168.1.3
#DSR_IP=192.168.2.10
#DSR_BACK1=$TRP_BACK1
#DSR_BACK2=$TRP_BACK2
#DSR_MYIP=$TRP_MYIP
#TARPIT_IP=192.168.2.11

if test ! -z "$TRP_PEN"; then
	echo
	echo "Testing Transparent Reverse Proxy, TCP"
	stop_pen
	ssh root@$TRP_PEN "cd Git/pen && git pull && make && killall pen ; ./pen -r -O transparent 80 $TRP_BACK1 $TRP_BACK2"
	H=`curl -s http://$TRP_PEN/cgi-bin/remote_addr`
	check_result "Transparent result" "$TRP_MYIP" "$H"
	ssh root@$TRP_PEN "cd Git/pen && killall pen ; ./pen -r 80 $TRP_BACK1 $TRP_BACK2"
	H=`curl -s http://$TRP_PEN/cgi-bin/remote_addr`
	check_different "Nontransparent result" "$TRP_MYIP" "$H"
	echo Success

	echo
	echo "Testing Transparent Reverse Proxy, UDP"
	stop_pen
	ssh root@$TRP_PEN "cd Git/pen && ./pen -r -O transparent -U 53 $TRP_BACK1 $TRP_BACK2"
	H=`dig +short @$TRP_PEN -x 127.0.0.1`
	check_result "Transparent result" "localhost." "$H"
	echo Success
fi

if test ! -z "$DSR_PEN"; then
	echo
	echo "Testing Direct Server Return and Tarpit"
	stop_pen
	ssh root@$DSR_PEN "cd Git/pen && git pull && make && killall pen ; ./pen -r -O 'acl 1 permit $TARPIT_IP' -O 'tarpit_acl 1' -O 'dsr_if eth1' $DSR_IP:80 $DSR_BACK1 $DSR_BACK2"
	echo
	H=`nmap -p 80 $TARPIT_IP|grep ^80/tcp|awk '{print $2}'`
	check_result "Nmap result from legitimate address" "open" "$H"
	H=`curl -s http://$DSR_IP/cgi-bin/remote_addr`
	check_result "Curl result from legitimate address" "$DSR_MYIP" "$H"
	H=`nmap -p 80 $TARPIT_IP|grep ^80/tcp|awk '{print $2}'`
	check_result "Nmap result from tarpitted address" "open" "$H"
	H=`curl -s -m 3 http://$TARPIT_IP/cgi-bin/remote_addr`
	E=$?
	echo "Curl exit code: $E"
	echo "Curl result from tarpitted address: $H"
	if test "$E" = "0"; then
		fail "Wrong curl exit code"
	fi
	echo Success
fi

stop_pen

exit 0

# Stuff that needs to be prepared for this script to work:

# Apache with four virtual hosts on different ports:
Listen 100
Listen 101
Listen 102
Listen 103
<VirtualHost *:100>
        DocumentRoot /var/www/html/100
</VirtualHost>
<VirtualHost *:101>
        DocumentRoot /var/www/html/101
</VirtualHost>
<VirtualHost *:102>
        DocumentRoot /var/www/html/102
</VirtualHost>
<VirtualHost *:103>
        DocumentRoot /var/www/html/103
</VirtualHost>

# find /var/www/html/??? -name index.html -exec echo -n {} ": " \; -exec cat {} \;
/var/www/html/100/index.html : 100
/var/www/html/101/index.html : 101
/var/www/html/102/index.html : Emergency
/var/www/html/103/index.html : Abuse

# And a bind with split horizon, serving only example.com:

acl view1 {
        127.0.0.0/8;
};

acl view2 {
        10.0.0.0/8;
};

view "view1" {
        match-clients { view1; };
        zone "example.com" IN {
                type master;
                file "/etc/bind/db.example.com.view1";
        };
};

view "view2" {
        match-clients { view2; };
        zone "example.com" IN {
                type master;
                file "/etc/bind/db.example.com.view2";
        };
};

# cat db.example.com.view1
$TTL    3h
@       IN      SOA     localhost. root.localhost. (
                        1
                        604800
                        86400
                        2419200
                        604800 )
@       IN      NS      localhost.
@       IN      A       1.1.1.1

# cat db.example.com.view2
$TTL    3h
@       IN      SOA     localhost. root.localhost. (
                        1
                        604800
                        86400
                        2419200
                        604800 )
@       IN      NS      localhost.
@       IN      A       2.2.2.2

