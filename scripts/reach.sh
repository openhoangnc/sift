#!/bin/sh
# Works out where a connection to a Sift server breaks, run from the network
# that cannot reach it, while it cannot.
#
#   sh reach.sh homeguard.example.org
#   sh reach.sh -a 203.0.113.7 homeguard.example.org   # this address, not DNS's
#   sh reach.sh -p 8443 homeguard.example.org          # HTTPS on another port
#   sh reach.sh -n homeguard.example.org               # skip the public-IP lookup
#
# It needs curl, and dig, getent, host or nslookup for the local lookup.
#
# The three places a connection home can fail look different from outside,
# and that is all this relies on:
#
#   - Nothing answers the TCP connection: the address is not yours any more,
#     or the router, your ISP, or this network drops it on the way.
#   - The connection is made and cut before TLS finishes.  Sift does exactly
#     this to a source it is refusing -- it accepts, then closes before the
#     handshake -- and it does it by address, without looking at the name.
#     A filter on this network that works by name cuts the connection only
#     when it carries the name, so the same address dialled bare goes
#     through.  That one comparison tells the two apart.
#   - TLS completes with a certificate that is not yours: something on this
#     network intercepts it.
#
# What it sends, and to whom:
#
#   - api.ipify.org and api6.ipify.org are asked for this machine's public
#     address, which is what to look for in Sift's log (-n skips this);
#   - 1.1.1.1 is asked for the name over HTTPS, beside this network's own
#     resolver, so a stale or rewritten answer shows;
#   - the server is asked for / -- by name, and by bare address if that
#     failed -- and nothing else.  Each of those is a request Sift answers,
#     so neither counts against this address with its connection guard.
#
# Connections go direct even when a proxy is configured, because the
# question is whether the direct path works.

set -u

PORT=443
LOOKUP_IP=1
ADDRS=
CONNECT_TIMEOUT=6
MAX_TIME=15

usage() {
	echo "usage: $0 [-p port] [-a address]... [-n] host" >&2
	exit 2
}

while getopts p:a:nh opt; do
	case $opt in
	p) PORT=$OPTARG ;;
	a) ADDRS="$ADDRS $OPTARG" ;;
	n) LOOKUP_IP=0 ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage
HOST=$1

command -v curl >/dev/null 2>&1 || {
	echo "curl is needed" >&2
	exit 2
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t reach)
trap 'rm -rf "$tmp"' EXIT INT TERM

# Seconds, as curl reports them, in whole milliseconds.
ms() {
	awk -v s="$1" 'BEGIN { printf "%d", s * 1000 + 0.5 }'
}

# Whether curl's seconds are above zero: a phase that never happened is
# reported as 0.
happened() {
	awk -v s="$1" 'BEGIN { exit !(s > 0) }'
}

is_v6() {
	case $1 in *:*) return 0 ;; *) return 1 ;; esac
}

# The /64 an IPv6 address is judged as, written the way Sift's log writes it:
# lowercase, no leading zeros, the longest run of zero groups as "::".
slash64() {
	echo "$1" | awk '{
		a = tolower($0)
		i = index(a, "::")
		if (i) {
			l = substr(a, 1, i - 1); r = substr(a, i + 2)
			nl = l == "" ? 0 : split(l, L, ":")
			nr = r == "" ? 0 : split(r, R, ":")
			for (k = 1; k <= nl; k++) g[k] = L[k]
			for (k = nl + 1; k <= 8 - nr; k++) g[k] = "0"
			for (k = 1; k <= nr; k++) g[8 - nr + k] = R[k]
		} else {
			split(a, g, ":")
		}
		for (k = 1; k <= 8; k++) {
			if (k > 4) g[k] = "0"
			sub(/^0+/, "", g[k]); if (g[k] == "") g[k] = "0"
		}
		best = 0; at = 0
		for (k = 1; k <= 8; k++) {
			if (g[k] != "0") continue
			for (e = k; e <= 8 && g[e] == "0"; e++);
			if (e - k > best) { best = e - k; at = k }
			k = e
		}
		out = ""
		for (k = 1; k < at; k++) out = out (k > 1 ? ":" : "") g[k]
		out = out "::"
		for (k = at + best; k <= 8; k++) out = out g[k] (k < 8 ? ":" : "")
		print out "/64"
	}'
}

# This network's resolver, one record type: one address per line.
local_lookup() {
	if command -v dig >/dev/null 2>&1; then
		dig +short +time=3 +tries=1 "$HOST" "$1" 2>/dev/null
	elif command -v getent >/dev/null 2>&1; then
		# getent maps IPv4 into IPv6 when asked for AAAA and there is none.
		if [ "$1" = A ]; then
			getent ahostsv4 "$HOST" 2>/dev/null | awk '{ print $1 }'
		else
			getent ahostsv6 "$HOST" 2>/dev/null | awk '{ print $1 }' | grep -v '^::ffff:'
		fi
	elif command -v host >/dev/null 2>&1; then
		host -t "$1" "$HOST" 2>/dev/null | awk '/has (IPv6 )?address/ { print $NF }'
	elif command -v nslookup >/dev/null 2>&1; then
		nslookup -type="$1" "$HOST" 2>/dev/null |
			awk '/^Name:/ { named = 1 } named && /^Address/ { print $NF }'
	fi | only "$1"
}

# 1.1.1.1 over HTTPS, one record type.
doh_lookup() {
	curl -sS --max-time 6 -H 'accept: application/dns-json' \
		"https://1.1.1.1/dns-query?name=$HOST&type=$1" 2>/dev/null |
		grep -o '"data": *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' | only "$1"
}

# Keeps the lines that are addresses of the type asked for: an answer can
# carry the CNAME it was reached through.
only() {
	if [ "$1" = A ]; then
		grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
	else
		grep -E '^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*$'
	fi | sort -u
}

# One line, the addresses space-separated, or "none".
joined() {
	j=$(tr '\n' ' ' | sed 's/ *$//')
	echo "${j:-none}"
}

# Fetches / once, setting P_CODE (curl's exit status), P_HTTP, P_TCP and
# P_TLS (curl's cumulative seconds), P_ERR, P_ISSUER and P_SERVER.
probe() {
	: >"$tmp/head"
	w=$(curl -sS -v --noproxy '*' -o /dev/null -D "$tmp/head" \
		--connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
		-w '%{http_code} %{time_connect} %{time_appconnect}' \
		"$@" 2>"$tmp/err")
	P_CODE=$?
	# shellcheck disable=SC2086
	set -- $w
	P_HTTP=${1:-000}
	P_TCP=${2:-0}
	P_TLS=${3:-0}
	P_ERR=$(grep '^curl: (' "$tmp/err" | tail -n 1 | sed 's/^curl: ([0-9]*) //; s/ *$//')
	P_ISSUER=$(sed -n 's/^\*  *issuer: //p' "$tmp/err" | head -n 1)
	P_SERVER=$(tr -d '\r' <"$tmp/head" | sed -n 's/^[Ss]erver: *//p' | head -n 1)
}

# Names what the last probe came to, in P_KIND.
classify() {
	if [ "$P_CODE" -eq 0 ]; then
		P_KIND=reached
	elif [ "$P_CODE" -eq 60 ] || [ "$P_CODE" -eq 51 ]; then
		P_KIND=cert
	elif ! happened "$P_TCP"; then
		# A timeout is 28.  Anything else failed at once, and curl's own
		# message no longer says why; its trace says so for a refusal.
		if [ "$P_CODE" -eq 28 ]; then
			P_KIND=silent
		elif grep -qi 'connection refused' "$tmp/err"; then
			P_KIND=refused
		else
			P_KIND=noroute
		fi
	elif ! happened "$P_TLS"; then
		case $P_CODE:$P_ERR in
		28:*) P_KIND=stalled ;;
		*:*alert*) P_KIND=alert ;;
		*) P_KIND=cut ;;
		esac
	else
		P_KIND=after
	fi
}

# What the last probe did, on one line.
timeline() {
	t="TCP"
	if happened "$P_TCP"; then
		t="$t $(ms "$P_TCP") ms"
		if happened "$P_TLS"; then
			t="$t, TLS +$(ms "$(awk -v a="$P_TLS" -v b="$P_TCP" 'BEGIN { print a - b }')") ms"
		else
			t="$t, TLS failed"
		fi
	else
		t="$t failed"
	fi
	if [ "$P_CODE" -eq 0 ]; then
		t="$t, HTTP $P_HTTP"
	elif [ -n "$P_ERR" ]; then
		t="$t: $P_ERR"
	fi
	echo "$t"
}

say() {
	printf '%s\n' "$*" | fold -s -w 76 | sed 's/^/      /'
}

echo "Reaching $HOST on port $PORT"
echo "  at $(date -u +%Y-%m-%dT%H:%M:%SZ) -- Sift logs in UTC, so look there"
if [ -n "${HTTPS_PROXY:-}${https_proxy:-}${ALL_PROXY:-}${all_proxy:-}" ]; then
	echo "  a proxy is configured here; this check goes around it"
fi
echo

ME4=
ME6=
if [ "$LOOKUP_IP" -eq 1 ]; then
	ME4=$(curl -4 -sS --noproxy '*' --max-time 6 https://api.ipify.org 2>/dev/null | only A)
	ME6=$(curl -6 -sS --noproxy '*' --max-time 6 https://api6.ipify.org 2>/dev/null | only AAAA)
	echo "This machine, as the internet sees it"
	echo "  IPv4  ${ME4:-none}"
	echo "  IPv6  ${ME6:-none}"
	echo
fi

LOCAL4=$(local_lookup A | joined)
LOCAL6=$(local_lookup AAAA | joined)
DOH4=$(doh_lookup A | joined)
DOH6=$(doh_lookup AAAA | joined)

echo "The name"
printf '  %-28s A %s   AAAA %s\n' "this network's resolver" "$LOCAL4" "$LOCAL6"
printf '  %-28s A %s   AAAA %s\n' "1.1.1.1, over HTTPS" "$DOH4" "$DOH6"

dns_note=
if [ "$LOCAL4 $LOCAL6" = "none none" ] && [ "$DOH4 $DOH6" = "none none" ]; then
	dns_note="Neither resolver has an address for the name. If the record is kept by dynamic DNS, it may not have been updated, or 1.1.1.1 could not be reached from here either."
elif [ "$LOCAL4 $LOCAL6" = "none none" ]; then
	dns_note="This network's resolver has no address for the name, and 1.1.1.1 does: the network's DNS is failing or filtering it. That is on this side, not at home."
elif [ "$DOH4 $DOH6" != "none none" ] && [ "$LOCAL4 $LOCAL6" != "$DOH4 $DOH6" ]; then
	dns_note="The two resolvers disagree. If your home address changed recently, this network may still hold the old one; otherwise it is rewriting the answer. Compare both with the WAN address your router shows."
fi
if [ -n "$dns_note" ]; then
	echo
	say "$dns_note"
fi
echo

if [ -z "$ADDRS" ]; then
	ADDRS=$(printf '%s\n' $LOCAL4 $LOCAL6 $DOH4 $DOH6 | grep -v '^none$' | sort -u)
fi
if [ -z "$ADDRS" ]; then
	echo "No address to try. Give one with -a, such as the WAN address your router shows."
	exit 1
fi

seen=
for addr in $ADDRS; do
	if is_v6 "$addr"; then
		pinned="[$addr]"
	else
		pinned=$addr
	fi

	echo "$addr"
	probe --resolve "$HOST:$PORT:$pinned" "https://$HOST:$PORT/"
	classify
	KIND=$P_KIND
	printf '  %-12s %s\n' "by name" "$(timeline)"
	[ -n "$P_SERVER" ] && say "Answered with \"Server: $P_SERVER\". Sift sends no Server header, so this is something else."

	case $KIND in
	reached)
		case $P_HTTP in
		429) say "Sift's sign-in limiter answered: the server is reachable, and sign-ins from this address are paused for a while after too many wrong passwords." ;;
		*) say "Reached." ;;
		esac
		;;
	cert)
		# curl stops before describing a certificate it rejects.
		probe -k --resolve "$HOST:$PORT:$pinned" "https://$HOST:$PORT/"
		say "This machine does not trust the certificate it was given${P_ISSUER:+, issued by: $P_ISSUER}. If that is not who issued yours, something on this network intercepts HTTPS: a captive portal, a company's inspecting proxy, or antivirus here. If it is, this machine's own certificate store is out of date."
		;;
	refused)
		say "Something at this address refused the connection. The router is not forwarding port $PORT, Sift is not listening on it, or a firewall answered for them."
		;;
	noroute)
		if is_v6 "$addr"; then
			say "No IPv6 route from here. Browsers on this network will use IPv4, so this one is harmless unless IPv4 fails too."
		else
			say "No route to the address from here: this network, or the path from it, cannot reach it."
		fi
		;;
	silent)
		say "Nothing answered within ${CONNECT_TIMEOUT} s. The address may not be yours any more (has your home IP changed?), or the router, your home ISP, or this network drops the connection. Try from a third network, such as a phone on mobile data: if that fails too, the problem is at home."
		;;
	cut | stalled | alert)
		probe -k "https://$pinned:$PORT/"
		classify
		BARE=$P_KIND
		printf '  %-12s %s\n' "bare" "$(timeline)"
		if [ "$BARE" = reached ]; then
			say "Cut when the connection names $HOST, and served when it does not. Sift never looks at the name before it refuses a source, so this is filtering on this network or its ISP."
		elif [ "$KIND" = cut ] && [ "$BARE" = cut ]; then
			say "Connected, then closed before TLS, by name and bare alike. That is how Sift refuses a source it has banned: look for this machine's public address in its log. If it is not there, something between here and home is cutting every connection to the address."
			seen="$seen ban"
		elif [ "$KIND" = stalled ]; then
			say "Connected, then the handshake went unanswered. Sift never does that to a source it refuses -- it closes at once -- so something on the path is holding the connection."
		else
			say "TLS was refused with an alert. Sift answers alerts only on DNS-over-TLS, with tls.strict_sni_check; on this port it is something else."
		fi
		;;
	after)
		say "TLS completed and HTTP then failed. If the connection was cut, something inspecting traffic did it after the handshake."
		;;
	esac

	if [ "$KIND" != reached ] && happened "$P_TCP" && [ "$(ms "$P_TCP")" -lt 2 ]; then
		say "The connection was made in under 2 ms, which is faster than any trip home from another network: something close by answered for this address."
	fi
	echo
done

case $seen in
*ban*)
	echo "Looking for a ban in Sift's log"
	for me in $ME4 $ME6; do
		if is_v6 "$me"; then
			# An IPv6 source is judged, and logged, as its /64.
			echo "  grep 'refusing a source' <log> | grep -F 'source=$(slash64 "$me") '"
		else
			echo "  grep 'refusing a source' <log> | grep -F 'client=$me '"
		fi
	done
	[ -n "$ME4$ME6" ] || echo "  grep 'refusing a source' <log>    (and this machine's public address)"
	echo "  grep 'turning connections away' <log>"
	say "The first is a ban: 10 minutes the first time, doubling for each one within a day of the last. Adding the address to ratelimit_whitelist exempts it, and lifts a ban as soon as the DNS settings are saved. The second is Sift at a limit on what the internet may hold open at once: it holds nothing against anyone, and passes as connections close."
	;;
esac
