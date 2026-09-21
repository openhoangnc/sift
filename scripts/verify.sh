#!/bin/sh
# Runs every compatibility check against a real AdGuard Home.
#
# Builds the Go reference from upstream/, starts it and sift side by
# side on high ports with the same configuration, and compares their config
# output, DNS answers, HTTP API and statistics database.

set -e -u

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${SIFT_VERIFY_DIR:-${TMPDIR:-/tmp}/sift-verify}"

go_http=14000
go_dns=14053
rs_http=14001
rs_dns=14054
user=admin
pass=verify123
# bcrypt of "verify123", cost 10.
hash='$2a$10$yM2G0G0bbDkstqZFACqR.eZaAUfNTyCueDK0M8yiR5vfue1okoXmO'

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

cleanup() {
	[ -n "${go_pid:-}" ] && kill "$go_pid" 2>/dev/null || true
	[ -n "${rs_pid:-}" ] && kill "$rs_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

say "workspace tests"
cd "$root"
cargo test --workspace --quiet || fail "the test suite did not pass"

say "building both servers"
[ -d "$root/upstream" ] || fail "no upstream checkout at $root/upstream"
( cd "$root/upstream" && go build -o "$work/AdGuardHome-go" . ) 2>/dev/null || {
	mkdir -p "$work"
	( cd "$root/upstream" && go build -o "$work/AdGuardHome-go" . )
}
cargo build --release --quiet -p sift

rm -rf "$work/go" "$work/rust"
mkdir -p "$work/go/conf" "$work/go/work/data/filters" "$work/rust/conf" "$work/rust/work/data/filters"

seed_config() {
	cat > "$1/conf/AdGuardHome.yaml" <<EOF
http:
  address: 127.0.0.1:$2
users:
  - name: $user
    password: $hash
dns:
  bind_hosts:
    - 127.0.0.1
  port: $3
  ratelimit: 0
  # Written out rather than left to the default, because the DNSSEC shape
  # comparison only means anything while signatures are being asked for.
  enable_dnssec: true
  # Likewise: with no TLS configured below there is nothing for either server
  # to advertise over DDR, which is exactly the case that used to be forwarded.
  handle_ddr: true
schema_version: 34
EOF
}
seed_config "$work/go" "$go_http" "$go_dns"
seed_config "$work/rust" "$rs_http" "$rs_dns"

say "starting the Go reference"
"$work/AdGuardHome-go" --no-check-update --no-permcheck \
	-c "$work/go/conf/AdGuardHome.yaml" -w "$work/go/work" > "$work/go.log" 2>&1 &
go_pid=$!
sleep 12

# Reuse the filter list the Go build downloaded, so both engines see the same rules.
cp "$work/go/work/data/filters/"*.txt "$work/rust/work/data/filters/" 2>/dev/null || true

say "starting sift"
"$root/target/release/AdGuardHome" --no-check-update \
	-c "$work/rust/conf/AdGuardHome.yaml" -w "$work/rust/work" > "$work/rust.log" 2>&1 &
rs_pid=$!
sleep 6

say "HTTP API response shapes"
python3 "$root/tests/compat/api_diff.py" \
	--go "http://127.0.0.1:$go_http" --rust "http://127.0.0.1:$rs_http" \
	--go-dns-port "$go_dns" --rust-dns-port "$rs_dns" \
	--user "$user" --password "$pass" || fail "the API shapes differ"

say "DNS answers"
corpus="$work/corpus.txt"
grep -oE '^\|\|[a-z0-9.-]+\^$' "$work/rust/work/data/filters/"*.txt 2>/dev/null \
	| sed 's/.*||//; s/\^$//' | sort -u | head -400 > "$corpus" || true
printf '%s\n' google.com github.com example.com cloudflare.com >> "$corpus"
python3 "$root/tests/compat/dns_diff.py" \
	--go "127.0.0.1:$go_dns" --rust "127.0.0.1:$rs_dns" --corpus "$corpus" --workers 6 \
	|| fail "DNS answers differ"

say "DNSSEC response shapes"
python3 "$root/tests/compat/dnssec_diff.py" \
	--go "127.0.0.1:$go_dns" --rust "127.0.0.1:$rs_dns" \
	|| fail "responses carry different DNSSEC records, AD bits or OPT records"

say "UDP truncation"
python3 "$root/tests/compat/truncate_diff.py" \
	--go "127.0.0.1:$go_dns" --rust "127.0.0.1:$rs_dns" \
	|| fail "an oversized answer was not cut to what the client asked for"

say "resolver discovery"
python3 "$root/tests/compat/ddr_diff.py" \
	--go "127.0.0.1:$go_dns" --rust "127.0.0.1:$rs_dns" \
	|| fail "the resolver-discovery name is not answered the same way"

# The last two change a setting to do their work, so they run after every
# comparison that does not.  This one replaces the user rules -- a rewrite
# exception only means anything beside the rewrite it excepts -- and puts the
# originals back.
say "\$dnsrewrite exceptions"
python3 "$root/tests/compat/dnsrewrite_diff.py" \
	--go "http://127.0.0.1:$go_http" --rust "http://127.0.0.1:$rs_http" \
	--go-dns-port "$go_dns" --rust-dns-port "$rs_dns" \
	--user "$user" --password "$pass" \
	|| fail "\$dnsrewrite rules and their exceptions are handled differently"

# Last of the DNS comparisons, because the rate limit has to be on to be
# visible and the seeded config turns it off so the comparisons above are not
# throttled.  It puts the old value back, which also puts `ratelimit` through
# the config round-trip the next step checks.
say "rate limiting per transport"
python3 "$root/tests/compat/ratelimit_diff.py" \
	--go "http://127.0.0.1:$go_http" --rust "http://127.0.0.1:$rs_http" \
	--go-dns-port "$go_dns" --rust-dns-port "$rs_dns" \
	--user "$user" --password "$pass" \
	|| fail "the rate limit does not apply to the same transports"

say "config output"
for port in "$go_http" "$rs_http"; do
	curl -sf --max-time 10 -u "$user:$pass" -X POST -H 'Content-Type: application/json' \
		-d '{"rules":["||ads.example.com^","@@||good.example.com^"]}' \
		"http://127.0.0.1:$port/control/filtering/set_rules" > /dev/null
	curl -sf --max-time 10 -u "$user:$pass" -X POST -H 'Content-Type: application/json' \
		-d '{"domain":"*.internal.lan","answer":"10.0.0.1"}' \
		"http://127.0.0.1:$port/control/rewrite/add" > /dev/null
done
sleep 2
sed -e "s/127.0.0.1:$go_http/HTTP/" -e "s/port: $go_dns/DNS/" "$work/go/conf/AdGuardHome.yaml" > "$work/go.norm"
sed -e "s/127.0.0.1:$rs_http/HTTP/" -e "s/port: $rs_dns/DNS/" "$work/rust/conf/AdGuardHome.yaml" > "$work/rust.norm"
diff -u "$work/go.norm" "$work/rust.norm" || fail "the config files differ"
echo "config files are byte-identical"

say "statistics handover"
for i in $(seq 1 12); do
	dig @127.0.0.1 -p "$rs_dns" "probe$i.example.com" A +timeout=3 > /dev/null 2>&1 || true
done
kill -INT "$rs_pid"; wait "$rs_pid" 2>/dev/null || true; rs_pid=
sleep 2
[ -f "$work/rust/work/data/stats.db" ] || fail "sift wrote no statistics database"

cp "$work/rust/work/data/stats.db" "$work/go/work/data/stats.db"
kill -INT "$go_pid"; wait "$go_pid" 2>/dev/null || true
"$work/AdGuardHome-go" --no-check-update --no-permcheck \
	-c "$work/go/conf/AdGuardHome.yaml" -w "$work/go/work" > "$work/go2.log" 2>&1 &
go_pid=$!
sleep 12
total=$(curl -sf --max-time 10 -u "$user:$pass" "http://127.0.0.1:$go_http/control/stats" \
	| python3 -c 'import sys,json; print(json.load(sys.stdin)["num_dns_queries"])')
[ "${total:-0}" -gt 0 ] || fail "the Go build read no statistics from the database sift wrote"
echo "Go read $total queries from the database sift wrote"

printf '\n\033[32mall compatibility checks passed\033[0m\n'
