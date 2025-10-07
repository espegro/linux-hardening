#!/usr/bin/env bash
# laurel-watch.sh — interaktiv visning av exec + nettverk fra Laurel/Auditd
# Krever: jq >= 1.6, tail
# Sikkerhetspraksis: set -euo pipefail, defensiv parsing, trap for tempfil.

set -euo pipefail

LOG="/var/log/laurel/audit.log"
SHOW_UNIX=0        # 1 = vis UNIX-domain sockets (ex. /var/run/*.sock)
DROP_NSCD=1        # 1 = dropp nscd-støy (UNIX /var/run/nscd/socket)
MAP_SERVICES=1     # 1 = map velkjente porter til (ssh),(http),…
INTERACTIVE_NET=0  # 1 = vis bare nett fra TTY; 0 = vis også uten TTY (tmux/bakgrunn)

usage() {
  cat <<EOF
Usage: $(basename "$0") [--log PATH] [--show-unix] [--include-nscd] [--no-service-names] [--interactive-net-only]

Options:
  --log PATH               Path til Laurel JSONL (default: $LOG)
  --show-unix              Vis UNIX-domain sockets (default: skjult)
  --include-nscd           Ikke dropp /var/run/nscd/socket (default: droppes)
  --no-service-names       Ikke mapp porter til (ssh),(http),…
  --interactive-net-only   Vis nett bare når .SYSCALL.tty er pts/tty
  -h, --help               Denne hjelpen

Tips:
  - For å se IP/PORT i CONNECT/BIND bør Laurel ha [translate] universal=true og user-db=true
  - Sørg for audit-regler for connect/bind/listen/accept/sendto/recvfrom/…
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log) LOG="${2:-}"; shift 2;;
    --show-unix) SHOW_UNIX=1; shift;;
    --include-nscd) DROP_NSCD=0; shift;;
    --no-service-names) MAP_SERVICES=0; shift;;
    --interactive-net-only) INTERACTIVE_NET=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Ukjent flagg: $1" >&2; usage; exit 2;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "Feil: jq mangler"; exit 1; }
command -v tail >/dev/null 2>&1 || { echo "Feil: tail mangler"; exit 1; }

# Sjekk jq-versjon (min 1.6)
if ! jq -n '1' >/dev/null 2>&1; then
  echo "Feil: jq ser ut til å være for gammel." >&2
  exit 1
fi

JQ_PROG="$(mktemp -t laurel_net_exec.XXXXXX.jq)"
trap 'rm -f "$JQ_PROG"' EXIT

cat >"$JQ_PROG" <<'JQ'
# jq-filter for å formatere Laurel JSON-line events
# Virker med jq 1.6

def ts:
  ( .TS // (.ID? | split(":")[0]) ) as $raw
  | ( if ($raw|type)=="number" then $raw else ($raw|tostring|split(".")[0]|tonumber? // now) end )
  | strftime("%F %T");

def norm_tty:
  (.SYSCALL.tty? | tostring) as $t
  | if ($t=="(none)" or $t=="none" or $t=="") then "-" else $t end;

def auid_s: (.SYSCALL.AUID // .SYSCALL.auid // "unset") | tostring;
def euid_s: (.SYSCALL.EUID // .SYSCALL.euid // "?") | tostring;

def who:
  auid_s as $a | euid_s as $e
  | if $a != $e then ($a + "->" + $e) else $a end;

def userish:
  auid_s as $a
  | ($a != "unset" and $a != "?"
     and ( $a == "0"
           or ( ($a|tonumber? // -1) >= 1000 )
           or ( $a|test("[A-Za-z]") ) ) );

# Tjenestenavn for kjente porter
# Returnerer f.eks. "(ssh)" eller "" hvis ukjent.
def svcname($port):
  if $ENV.MAP_SERVICES == "0" then "" else
    ( $port|tonumber? ) as $p
    | if    $p==22   then "(ssh)"
      elif  $p==80   then "(http)"
      elif  $p==443  then "(https)"
      elif  $p==53   then "(dns)"
      elif  $p==25   then "(smtp)"
      elif  $p==110  then "(pop3)"
      elif  $p==143  then "(imap)"
      elif  $p==587  then "(submission)"
      elif  $p==993  then "(imaps)"
      elif  $p==995  then "(pop3s)"
      elif  $p==3306 then "(mysql)"
      elif  $p==5432 then "(postgres)"
      elif  $p==6379 then "(redis)"
      elif  $p==8080 then "(http-alt)"
      elif  $p==27017 then "(mongodb)"
      else "" end
  end;

# Hent ut en representativ socket-endepunkt-streng:
#  - inet/inet6: "ADDR:PORT(svc)" (PORT kan være "?" hvis 0)
#  - local (UNIX): "UNIX:/path" (droppes hvis nscd og DROP_NSCD=1)
# Returnerer null for "dropp", eller en streng å skrive ut.
def netfmt($sc):
  if (.SOCKADDR|type) != "array" or (.SOCKADDR|length)==0 then
    "?"
  else
    # Finn første "nyttige" adresse (inet/inet6/local)
    ( .SOCKADDR[]
      | if has("SADDR") then .SADDR else . end
    ) as $c
    | if ($c.saddr_fam? // $c.FAMILY? // "") | test("^(inet6?|local)$") | not then
        "?"
      else
        if ($c.saddr_fam?=="local" or $c.FAMILY?=="local") then
          # UNIX socket
          ($c.path // $c.PATH // "?") as $p
          | if ($p=="/var/run/nscd/socket" and $ENV.DROP_NSCD=="1") then
              null
            elif $ENV.SHOW_UNIX=="1" then
              "UNIX:" + $p
            else
              null
            end
        else
          # inet/inet6
          ($c.addr // $c.ADDR // "?") as $addr
          | ($c.port // $c.PORT // 0) as $port
          | ($addr + ":" + (if ($port|tonumber? // 0) > 0 then ($port|tostring) else "?" end)
             + (svcname($port)))
        end
      end
  end;

def is_net($sc):
  ($sc=="connect" or $sc=="bind" or $sc=="listen" or $sc=="accept" or $sc=="accept4"
   or $sc=="sendto" or $sc=="recvfrom" or $sc=="sendmsg" or $sc=="recvmsg"
   or $sc=="getsockname" or $sc=="getpeername");

def cmdline:
  ( .EXECVE.ARGV? // .PROCTITLE.ARGV? // [] ) | map(@sh) | join(" ");

# Hovedstrøm
# 1) interaktiv exec
# 2) nett-hendelser fra "userish" (auid root eller >=1000), ev. begrenset til interaktivt hvis $ENV.INTERACTIVE_NET_ONLY == "1"
select(.SYSCALL?)
| (.SYSCALL.SYSCALL // .SYSCALL.syscall // "") as $sc
| (.SYSCALL.comm // "?") as $prog
| (norm_tty) as $tty
| (ts) as $ts
| (who) as $who
| ( .SYSCALL.ses // "?" | tostring ) as $ses
| if (($sc=="execve" or $sc=="execveat")
      and ($tty | test("^(pts|tty)")))
  then
    # Interaktiv exec fra TTY
    "\($ts) [\($tty)] \($who) ses=\($ses) cwd=\((.CWD.cwd // ".")) $ \(cmdline)"
  elif (is_net($sc) and userish
        and ( ($ENV.INTERACTIVE_NET_ONLY=="1" and ($tty|test("^(pts|tty)")))
              or ($ENV.INTERACTIVE_NET_ONLY!="1") ))
  then
    (netfmt($sc)) as $dst
    | if ($dst == null) then empty
      else "\($ts) [\($tty)] \($who) ses=\($ses) prog=\($prog) \(( $sc | ascii_upcase )) -> \($dst)"
      end
  else
    empty
  end
JQ

# Kjør streamen (tåler rotasjon pga -F)
# Vi sender noen flags via miljø til jq for enkel toggling
env MAP_SERVICES="$MAP_SERVICES" SHOW_UNIX="$SHOW_UNIX" DROP_NSCD="$DROP_NSCD" INTERACTIVE_NET_ONLY="$INTERACTIVE_NET" \
  tail -F -- "$LOG" | jq -r --unbuffered -f "$JQ_PROG"

