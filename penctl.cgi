#!/bin/sh

#  Copyright (C) 2002-2003  Ulric Eriksson <ulric@siag.nu>

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.

#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston,
#  MA 02111-1307, USA.

PENCTL=penctl

#set -x

header()
{
	if test -z "$1"; then
		TITLE=Penctl
	else
		TITLE="$1"
	fi
	cat << EOF
<html>
<head>
<title>$TITLE</title>
</head>
<body bgcolor="#ffffff">
<h1>$TITLE</h1>
EOF
}

footer()
{
	cat << EOF
</body>
</html>
EOF
}

errorpage()
{
	header "Error"
	echo "$1"
	footer
	exit 0
}

get_query()
{
	echo "$QUERY_STRING"|tr '&' '\n'|grep "^$1="|cut -f 2 -d =|sed -e 's,%2F,/,g' -e 's,%..,,g'
}

statuspage()
{
	test -z "$SERVER" && errorpage "No server"
	test -z "$PORT" && errorpage "No port"

	$PENCTL $SERVER:$PORT status 2> /tmp/penctl.cgi
	if test "$?" != "0"; then
		errorpage "`cat /tmp/penctl.cgi`"
	fi
	 echo "<form>"                                                          
                  echo '<input type="hidden" name="server" value="'$SERVER'">'   
                  echo '<input type="hidden" name="port" value="'$PORT'">'       
                  echo '<input type="submit" name="mode" value="Main">'          
          echo "</form>"
}

# testmode modelist setting
testmode()
{
	echo "$1"|egrep "no(\+| )$2" > /dev/null 2>&1
	if test "$?" = "0"; then
		echo "no"
	else
		echo "yes"
	fi
}

# setmode setting old new
setmode()
{
	if test "$2" != "$3"; then
		if test "$3" = "yes"; then
			$PENCTL $SERVER:$PORT $1
		else
			$PENCTL $SERVER:$PORT no $1
		fi
	fi
}

settingspage()
{
	test -z "$SERVER" && errorpage "No server"
	test -z "$PORT" && errorpage "No port"

	OLDMODE=`get_query oldmode`
	if test ! -z "$OLDMODE"; then
		BLACKLIST=`get_query blacklist`
		test -z "$BLACKLIST" || $PENCTL $SERVER:$PORT blacklist $BLACKLIST
		DEBUG=`get_query debug`
		test -z "$DEBUG" || $PENCTL $SERVER:$PORT debug $DEBUG
		LOG=`get_query log`
		test -z "$LOG" || $PENCTL $SERVER:$PORT log $LOG
		TIMEOUT=`get_query timeout`
		test -z "$TIMEOUT" || $PENCTL $SERVER:$PORT timeout $TIMEOUT
		TRACKING=`get_query tracking`
		test -z "$TRACKING" || $PENCTL $SERVER:$PORT tracking $TRACKING
		WEB_STATS=`get_query web_stats`
		test -z "$WEB_STATS" || $PENCTL $SERVER:$PORT web_stats $WEB_STATS
		x=`testmode "$OLDMODE" block`
		BLOCK=`get_query block`
		setmode "block" "$x" "$BLOCK"
		x=`testmode "$OLDMODE" delayed_forward`
		DFORWARD=`get_query dforward`
		setmode "dforward" "$x" "$DFORWARD"
		x=`testmode "$OLDMODE" hash`
		HASH=`get_query hash`
		setmode "hash" "$x" "$HASH"
#		HTTP=`get_query http`
#		setmode "$OLDMODE" "$x" "$HTTP"
		x=`testmode "$OLDMODE" roundrobin`
		ROUNDROBIN=`get_query roundrobin`
		setmode "roundrobin" "$x" "$ROUNDROBIN"
		x=`testmode "$OLDMODE" stubborn`
		STUBBORN=`get_query stubborn`
		setmode "stubborn" "$x" "$STUBBORN"
	fi

cat << EOF 1>&2
BLOCK="$BLOCK"
DFORWARD="$DFORWARD"
HASH="$HASH"
ROUNDROBIN="$ROUNDROBIN"
STUBBORN="$STUBBORN"
EOF

	header "Global Settings"
	BLACKLIST=`$PENCTL $SERVER:$PORT blacklist`
	CLIENTS_MAX=`$PENCTL $SERVER:$PORT clients_max`
	CONN_MAX=`$PENCTL $SERVER:$PORT conn_max`
	DEBUG=`$PENCTL $SERVER:$PORT debug`
	LISTEN=`$PENCTL $SERVER:$PORT listen`
	LOG=`$PENCTL $SERVER:$PORT log`
	MODE=`$PENCTL $SERVER:$PORT mode`
echo "<p><pre>MODE=$MODE</pre></p>"
	BLOCK=`testmode "$MODE" block`
	DFORWARD=`testmode "$MODE" delayed_forward`
	HASH=`testmode "$MODE" hash`
	ROUNDROBIN=`testmode "$MODE" roundrobin`
	STUBBORN=`testmode "$MODE" stubborn`
	PID=`$PENCTL $SERVER:$PORT pid`
	TIMEOUT=`$PENCTL $SERVER:$PORT timeout`
	TRACKING=`$PENCTL $SERVER:$PORT tracking`
	WEB_STATS=`$PENCTL $SERVER:$PORT web_stats`

	BLOCKCHECKED=""                                                                
	test x$BLOCK = xyes && BLOCKCHECKED=checked                                    
	DFORWARDCHECKED=""                                                             
	test x$DFORWARD = xyes && DFORWARDCHECKED=checked                              
	HASHCHECKED=""                                                                 
	test x$HASH = xyes && HASHCHECKED=checked                                      
	ROUNDROBINCHECKED=""                                                           
	test x$ROUNDROBIN = xyes && ROUNDROBINCHECKED=checked                          
	STUBBORNCHECKED=""                                                             
	test x$STUBBORN = xyes && STUBBORNCHECKED=checked                              
	
	cat << EOF
<form>
<table bgcolor="#c0c0c0">
<tr><td bgcolor="#80f080">Blacklist time</td><td><input size=5 type="text" name="blacklist" value="$BLACKLIST"></td></tr>
<tr><td bgcolor="#80f080">Max # of clients</td><td>$CLIENTS_MAX</td></tr>
<tr><td bgcolor="#80f080">Max # of connections</td><td>$CONN_MAX</td></tr>
<tr><td bgcolor="#80f080">Debug level</td><td><input size=5 type="text" name="debug" value="$DEBUG"></td></tr>
<tr><td bgcolor="#80f080">Listening port</td><td>$LISTEN</td></tr>
<tr><td bgcolor="#80f080">Logging destination</td><td><input type="text" name="log" value="$LOG"></td></tr>
<tr><td bgcolor="#80f080">Blocking</td><td><input type="checkbox" name="block" value="yes" $BLOCKCHECKED></td></tr>
<tr><td bgcolor="#80f080">Delayed forward</td><td><input type="checkbox" name="dforward" value="yes" $DFORWARDCHECKED></td></tr>
<tr><td bgcolor="#80f080">Hash</td><td><input type="checkbox" name="hash" value="yes" $HASHCHECKED></td></tr>
<!--tr><td bgcolor="#80f080">HTTP</td><td><input type="checkbox" name="http" value="yes"></td></tr-->
<tr><td bgcolor="#80f080">Roundrobin</td><td><input type="checkbox" name="roundrobin" value="yes" $ROUNDROBINCHECKED></td></tr>
<tr><td bgcolor="#80f080">Stubborn</td><td><input type="checkbox" name="stubborn" value="yes" $STUBBORNCHECKED></td></tr>
<tr><td bgcolor="#80f080">Process ID</td><td>$PID</td></tr>
<tr><td bgcolor="#80f080">Connect timeout</td><td><input size=5 type="text" name="timeout" value="$TIMEOUT"></td></tr>
<tr><td bgcolor="#80f080">Client tracking</td><td><input size=5 type="text" name="tracking" value="$TRACKING"></td></tr>
<tr><td bgcolor="#80f080">Web status report</td><td><input type="text" name="web_stats" value="$WEB_STATS"></td></tr>
</table>
<input type="hidden" name="oldmode" value="$MODE">
<input type="hidden" name="server" value="$SERVER">
<input type="hidden" name="port" value="$PORT">
<input type="submit" name="mode" value="Settings">
<input type="submit" name="mode" value="Main">
</form>
EOF

	footer
}

managepage()
{
	test -z "$SERVER" && errorpage "No server"
	test -z "$PORT" && errorpage "No port"

	N=0
	A=`get_query "A.$N"`
	while test ! -z "$A"; do
		P=`get_query "P.$N"`
		M=`get_query "M.$N"`
		H=`get_query "H.$N"`
		T=`get_query "T.$N"`
		x=""
		test -z "$A" || x="$x address $A"
		test -z "$P" || x="$x port $P"
		test -z "$M" || x="$x max $M"
		test -z "$H" || x="$x hard $H"
		test -z "$T" || x="$x blacklist $T"
		test -z "$x" || $PENCTL $SERVER:$PORT server $N $x
#		N=`echo $N+1|bc`
		N=$((N+1))
		A=`get_query "A.$N"`
	done

	header "Manage Servers"
	cat << EOF
<form><table bgcolor="#c0c0c0">
<tr>
<td bgcolor="#80f080">Server
<td bgcolor="#80f080">Address
<td bgcolor="#80f080">Port
<td bgcolor="#80f080">Conn
<td bgcolor="#80f080">Max
<td bgcolor="#80f080">Hard
<td bgcolor="#80f080">Sx
<td bgcolor="#80f080">Rx
<td bgcolor="#80f080">Blacklist
EOF
	$PENCTL $SERVER:$PORT servers | while read N a A p P c C m M h H s S r R; do
		cat << EOF
<tr>
<td>$N
<td><input type="text" name="A.$N" value="$A">
<td><input size=5 type="text" name="P.$N" value="$P">
<td>$C
<td><input size=5 type="text" name="M.$N" value="$M">
<td><input size=5 type="text" name="H.$N" value="$H">
<td>$S
<td>$R
<td><input size=5 type="text" name="T.$N" value="$T">
EOF
	done
	cat << EOF
</table>
<input type="hidden" name="server" value="$SERVER">
<input type="hidden" name="port" value="$PORT">
<input type="submit" name="mode" value="Manage">
<input type="submit" name="mode" value="Main">
</form>
EOF
}

mainpage()
{
	header
	cat << EOF
<form><table bgcolor="#c0c0c0">
<tr><td bgcolor="#80f080">Server<td><input type="text" name="server" value="$SERVER">
<tr><td bgcolor="#80f080">Port<td><input type="text" name="port" value="$PORT">
</table>
<input type="submit" name="mode" value="Status">
<input type="submit" name="mode" value="Manage">
<input type="submit" name="mode" value="Settings">
</form>
EOF
	footer
}


echo Content-type: text/html
echo

SERVER=`get_query server`
PORT=`get_query port`
MODE=`get_query mode`

case "$MODE" in
Status )
	statuspage
	;;
Manage )
	managepage
	;;
Settings )
	settingspage
	;;
* )
	mainpage
	;;
esac

