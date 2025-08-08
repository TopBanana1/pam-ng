#!/usr/bin/env bash
# pam-ng - Parsed Address Mapper - Next Generation
# Parse Nmap .gnmap or .xml and emit flexible, scriptable outputs.

set -euo pipefail

LC_ALL=C
FZF_BIN="${FZF_BIN:-fzf}"
export FZF_DEFAULT_OPTS="${FZF_DEFAULT_OPTS:---height=12 --reverse}"

# ------------------------- Defaults -------------------------
input_file="-"
output_file=""
pick_services=0
pick_ports=0
case_insensitive=0
unique=1
sort_output=1
web_only=0
format="{SERVICE}://{IP}:{PORT}"
service_re=".*"
port_re=".*"
proto_re=".*"
prefer_hostname=0
well_known=0
emit_json=0
emit_csv=0
csv_header=1
print0=0
group_mode=""   # "ip" or ""
field_sep=","
verbose=0
stream=0
build_index=-1   # -1=auto (only if pickers), 0=disable, 1=force
profile=""

declare -A PRESETS=(
  ["ip"]="{IP}"
  ["service"]="{SERVICE}"
  ["service_version"]="{SERVICE}: {VERSION}"
  ["url"]="{URL}"
  ["ip_port"]="{IP}:{PORT}"
  ["triplet"]="{SERVICE}{SEP}{IP}{SEP}{PORT}"
  ["full"]="{SERVICE} {VERSION} {PROTO} {IP}:{PORT}"
)

usage() {
  cat <<'USAGE'
pam-ng - Parse Nmap .gnmap or .xml and print selected fields

USAGE:
  pam-ng [INPUT.gnmap|INPUT.xml|-] [options]

OUTPUT TEMPLATES:
  -f/--format with tokens:
    {IP} {PORT} {PROTO} {SERVICE} {VERSION} {HOSTNAME} {URL} {SERVICE_INFO} {CPE} {OS} {SEP}
  Presets: ip, service, service_version, url, ip_port, triplet, full

OPTIONS:
  -o, --output FILE         Append output to FILE
  -f, --format STR|PRESET   Template or preset (default: {SERVICE}://{IP}:{PORT}, or {URL} with --web)
  --pick-services           fzf picker for services -> builds regex
  --pick-ports              fzf picker for ports -> builds regex
  -s, --service REGEX       Filter by service regex
  -p, --port REGEX          Filter by port regex
  --proto REGEX             Filter by protocol (e.g., ^tcp$)
  --web                     Only HTTP(S) services; default format becomes {URL}
  -i, --ignore-case         Case-insensitive filters
  --no-unique               Do not deduplicate lines
  --no-sort                 Preserve encounter order
  --prefer-hostname         Use hostname in {URL} if present
  --well-known              Fill empty services from common ports (80->http, 443->https, ...)
  --json                    Emit JSONL
  --csv                     Emit CSV (IP,PORT,PROTO,SERVICE,VERSION,HOSTNAME,URL,SERVICE_INFO,CPE,OS)
  --no-header               Omit CSV header
  --sep CHR                 CSV separator (default ",")
  --print0                  NUL-terminate records
  --group ip                Group output by IP (aggregate services/URLs)
  --stream                  Stream results, no dedupe/sort
  --index                   Always build pre-index for pickers
  --no-index                Never build pre-index
  --profile NAME            Preset for downstream tools: httpx | nuclei | gowitness
  -v, --verbose             Verbose diagnostics
  -h, --help                This help

NOTES:
  - INPUT "-" means stdin.
  - Auto-detects .xml vs .gnmap by header/extension.
  - XML parsing requires 'xmlstarlet'.
USAGE
}

# ------------------------- Argparse -------------------------
format_in=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) output_file="$2"; shift 2 ;;
    -f|--format) format_in="$2"; shift 2 ;;
    --pick-services) pick_services=1; shift ;;
    --pick-ports) pick_ports=1; shift ;;
    -s|--service) service_re="$2"; shift 2 ;;
    -p|--port) port_re="$2"; shift 2 ;;
    --proto) proto_re="$2"; shift 2 ;;
    --web) web_only=1; shift ;;
    -i|--ignore-case) case_insensitive=1; shift ;;
    --no-unique) unique=0; shift ;;
    --no-sort) sort_output=0; shift ;;
    --prefer-hostname) prefer_hostname=1; shift ;;
    --well-known) well_known=1; shift ;;
    --json) emit_json=1; shift ;;
    --csv) emit_csv=1; shift ;;
    --no-header) csv_header=0; shift ;;
    --sep) field_sep="$2"; shift 2 ;;
    --print0) print0=1; shift ;;
    --group) group_mode="$2"; shift 2 ;;
    --stream) stream=1; shift ;;
    --index) build_index=1; shift ;;
    --no-index) build_index=0; shift ;;
    --profile) profile="$2"; shift 2 ;;
    -v|--verbose) verbose=$((verbose+1)); shift ;;
    -h|--help) usage; exit 0 ;;
    -*)
      echo "Unknown option: $1" >&2; usage; exit 1 ;;
    *)
      if [[ "$input_file" == "-" ]]; then input_file="$1"; else
        echo "Duplicate input: $1" >&2; usage; exit 1
      fi
      shift ;;
  esac
done

tty_out=0; [[ -t 1 ]] && tty_out=1
tty_in=0; [[ -t 0 ]] && tty_in=1
if (( ! tty_in )); then pick_services=0; pick_ports=0; fi  # no interactive pickers if not a TTY

# Apply profile presets
apply_profile() {
  case "$profile" in
    httpx)
      web_only=1
      format="{URL}"
      unique=1
      ;;
    nuclei)
      # Often fed as -target URLs; prefer hostnames, collapse defaults
      web_only=1
      format="{URL}"
      prefer_hostname=1
      unique=1
      ;;
    gowitness)
      web_only=1
      format="{URL}"
      unique=1
      ;;
    "" ) ;;
    * ) echo "Unknown profile: $profile" >&2; exit 1 ;;
  esac
}
apply_profile

# resolve format (ignored by JSON/CSV grouping)
if [[ -z "$format_in" ]]; then
  if (( web_only )); then format_in="{URL}"; else format_in="{SERVICE}://{IP}:{PORT}"; fi
fi
if [[ -n "${PRESETS[$format_in]:-}" ]]; then
  format="${PRESETS[$format_in]}"
else
  format="$format_in"
fi
format="${format//\{SEP\}/$field_sep}"

# input exists?
if [[ "$input_file" != "-" && ! -f "$input_file" ]]; then
  echo "Input not found: $input_file" >&2; exit 1
fi

# Detect input type
detect_type() {
  local f="$1"
  if [[ "$f" != "-" ]]; then
    if [[ "$f" =~ \.xml$ ]]; then echo "xml"; return; fi
    if [[ "$f" =~ \.gnmap$ || "$f" =~ \.g$ ]]; then echo "gnmap"; return; fi
    # Peek first bytes
    if head -c 128 "$f" 2>/dev/null | grep -q '<nmaprun'; then echo "xml"; else echo "gnmap"; fi
  else
    # stdin: sniff
    if head -c 128 | tee /tmp/pam-ng.peek.$$ >/dev/null 2>&1; then :; fi
    if grep -q '<nmaprun' /tmp/pam-ng.peek.$$ 2>/dev/null; then echo "xml"; else echo "gnmap"; fi
  fi
}
input_type="$(detect_type "$input_file")"

# XML requires xmlstarlet
if [[ "$input_type" == "xml" ]] && ! command -v xmlstarlet >/dev/null 2>&1; then
  echo "xmlstarlet is required for XML input. Install it or provide .gnmap." >&2
  exit 1
fi

# Helpers
pick_from_fzf() {
  local list="$1"
  command -v "$FZF_BIN" >/dev/null 2>&1 || { echo ".*"; return; }
  local sel
  sel="$(printf "%s\n" "$list" | "$FZF_BIN" --multi --prompt="Select (TAB multi, ENTER accept): ")"
  [[ -z "$sel" ]] && { echo ".*"; return; }
  echo "$sel" | awk '{gsub(/([.^$*+?()[\]{}|\\])/,"\\\\&"); print "^" $0 "$"}' | paste -sd'|' - \
    | awk '{print "(" $0 ")"}'
}

well_known_map() {
  cat <<EOF
80	http
443	https
8080	http
8443	https
8000	http
8888	http
9443	https
8008	http
81	http
82	http
EOF
}

# Index building decision
if (( build_index == -1 )); then
  if (( pick_services || pick_ports )); then build_index=1; else build_index=0; fi
fi

wk_map="$(well_known_map)"

awk_flags=""
(( case_insensitive )) && awk_flags="-v IGNORECASE=1"

# ------------- Core Render & Filters (shared) -------------
render_block='
  function trim(s){ gsub(/^[ \t\r\n]+|[ \t\r\n]+$/,"",s); return s }
  function is_ipv6(s){ return (s ~ /:/) }
  function br_ip(s){ if (is_ipv6(s)) return "[" s "]"; else return s }
  function to_scheme(svc,tunnel) {
    if (tunnel ~ /(ssl|tls)/) return "https"
    if (svc ~ /^(https)$/ || svc ~ /(ssl|tls)\/http/) return "https"
    if (svc ~ /^http$/ || svc ~ /http-proxy/ || svc ~ /^rpc\.httpd$/) return "http"
    return ""
  }
  function json_escape(s,   r){ r=s; gsub(/\\/,"\\\\",r); gsub(/"/,"\\\"",r); gsub(/\t/,"\\t",r); gsub(/\r/,"\\r",r); gsub(/\n/,"\\n",r); return r }
  function csv_escape(s,   q){ q=s; gsub(/"/,"\"\"",q); return "\"" q "\"" }
  function out_render(ip,host,port,proto,svc,ver,url,svcinfo,cpe,os,   out) {
    if (emit_json) {
      printf("{\"ip\":\"%s\",\"port\":\"%s\",\"proto\":\"%s\",\"service\":\"%s\",\"version\":\"%s\",\"hostname\":\"%s\",\"url\":\"%s\",\"service_info\":\"%s\",\"cpe\":\"%s\",\"os\":\"%s\"}\n",
        json_escape(ip),json_escape(port),json_escape(proto),json_escape(svc),json_escape(ver),json_escape(host),json_escape(url),json_escape(svcinfo),json_escape(cpe),json_escape(os))
      next
    }
    if (emit_csv) {
      if (!printed_header && csv_header) {
        printf("IP%sPORT%sPROTO%sSERVICE%sVERSION%sHOSTNAME%sURL%sSERVICE_INFO%sCPE%sOS\n",
          csv_sep,csv_sep,csv_sep,csv_sep,csv_sep,csv_sep,csv_sep,csv_sep,csv_sep)
        printed_header=1
      }
      printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
        ip,csv_sep,port,csv_sep,proto,csv_sep,svc,csv_sep,ver,csv_sep,host,csv_sep,url,csv_sep,svcinfo,csv_sep,cpe,csv_sep,os)
      next
    }
    out=fmt
    gsub(/\{IP\}/, ip, out)
    gsub(/\{HOSTNAME\}/, host, out)
    gsub(/\{PORT\}/, port, out)
    gsub(/\{PROTO\}/, proto, out)
    gsub(/\{SERVICE\}/, svc, out)
    gsub(/\{VERSION\}/, ver, out)
    gsub(/\{URL\}/, url, out)
    gsub(/\{SERVICE_INFO\}/, svcinfo, out)
    gsub(/\{CPE\}/, cpe, out)
    gsub(/\{OS\}/, os, out)
    gsub(/\{SEP\}/, csv_sep, out)
    print trim(out)
  }
  function push_group(ip, s) { GROUP[ip] = (ip in GROUP) ? GROUP[ip] "\n" s : s }
'

# --------- GNMAP Parser (version-safe, IPv6-safe) ----------
parse_gnmap() {
  local in="${1}"
  awk $awk_flags \
    -v web_only="$web_only" \
    -v fmt="$format" \
    -v sre="$service_re" \
    -v preg="$port_re" \
    -v prre="$proto_re" \
    -v prefer_hostname="$prefer_hostname" \
    -v well_known="$well_known" \
    -v wk_map="$wk_map" \
    -v emit_json="$emit_json" \
    -v emit_csv="$emit_csv" \
    -v csv_sep="$field_sep" \
    -v csv_header="$csv_header" \
    -v group_mode="$group_mode" \
    -v stream="$stream" \
    '
    BEGIN {
      FS="\t"; OFS="\t"; printed_header=0
      # well-known
      n=split(wk_map, _wk, /\n/)
      for (i=1;i<=n;i++) { split(_wk[i], pair, /\t/); if (pair[1]!="") WK[pair[1]]=pair[2] }
    }
    '"$render_block"'
    # split ports safely: tokens separated by ", " but version may contain commas
    function split_ports_safe(s, outarr,   parts,i,j,acc,cnt,m) {
      cnt=0; acc=""; split(s, parts, /, /)
      for (i=1;i<=length(parts);i++) {
        if (acc=="") acc=parts[i]; else acc=acc ", " parts[i]
        # must have at least 7 slash fields
        split(acc, f, "/")
        if (length(f) >= 7) { outarr[++cnt]=acc; acc="" }
      }
      if (acc!="") outarr[++cnt]=acc
      return cnt
    }
    /^Host:/ && /Ports:/ {
      line=$0
      ip=$2
      host=$3; gsub(/^\(/,"",host); gsub(/\)$/,"",host)

      svcinfo=""
      si=index(line,"Service Info:"); if (si>0) svcinfo=trim(substr(line, si+13))

      p=index(line,"Ports:"); ports_sub=substr(line,p+6)
      ig=index(ports_sub,"Ignored "); if (ig>0) ports_sub=substr(ports_sub,1,ig-2)
      si2=index(ports_sub,"Service Info:"); if (si2>0) ports_sub=substr(ports_sub,1,si2-2)

      n=split_ports_safe(ports_sub, arr)
      for (i=1;i<=n;i++) {
        split(arr[i], f, "/")
        port=f[1]; state=f[2]; proto=f[3]; svc=f[5]
        ver=f[7]; if (length(f)>7) { # rejoin any extra / segments
          ver=""
          for (j=7;j<=length(f);j++) ver = (ver==""?f[j]:ver "/" f[j])
        }
        if (state !~ /^open/) continue
        if (svc=="" || svc=="unknown") { if (well_known && (port in WK)) svc=WK[port]; else if (svc=="") svc="unknown" }

        if (svc !~ sre) continue
        if (port !~ preg) continue
        if (proto !~ prre) continue

        scheme = to_scheme(svc,"")
        target = (prefer_hostname && host!="") ? host : ip
        url=""
        if (scheme!="") url = scheme "://" br_ip(target) ":" port
        if (web_only && url=="") continue

        if (group_mode=="ip") {
          item = (url!="") ? url : (svc ":" port)
          push_group(ip, item)
        } else {
          out_render(ip,host,port,proto,svc,ver,url,svcinfo,"","")
          if (stream) fflush()
        }
      }
    }
    END {
      if (group_mode=="ip") {
        for (h in GROUP) {
          if ('"$emit_json"') {
            n=split(GROUP[h], garr, /\n/)
            printf("{\"ip\":\"%s\",\"items\":[", json_escape(h))
            for (i=1;i<=n;i++){ if (i>1) printf(","); printf("\"%s\"", json_escape(garr[i])) }
            printf("]\n")
          } else if ('"$emit_csv"') {
            if (!printed_header && csv_header) { printf("IP%sITEMS\n", csv_sep); printed_header=1 }
            gsub(/\n/,"|",GROUP[h]); printf("%s%s%s\n", h, csv_sep, GROUP[h])
          } else {
            g=GROUP[h]; gsub(/\n/,", ",g); print h " -> " g
          }
        }
      }
    }
  ' "$in"
}

# --------- XML Parser (via xmlstarlet) ----------
parse_xml() {
  local in="${1}"
  # Pull fields; multiple CPEs joined by '|', OS guess by best accuracy
  xmlstarlet sel -t \
    -m '/nmaprun/host[status/@state="up"]' \
      -v 'address[@addrtype="ipv4" or @addrtype="ipv6"]/@addr' -o $'\t' \
      -v 'hostnames/hostname[1]/@name' -o $'\t' \
      -m 'ports/port[state/@state="open"]' \
        -v '@portid' -o $'\t' \
        -v '@protocol' -o $'\t' \
        -v 'service/@name' -o $'\t' \
        -v 'concat(service/@product, " ", service/@version, " ", service/@extrainfo)' -o $'\t' \
        -v 'service/@tunnel' -o $'\t' \
        -v 'normalize-space(string-join(service/cpe, "|"))' -o $'\t' \
        -b \
      -o $'\t' \
      -v 'os/osmatch[1]/@name' \
      -n \
  "$in" | awk $awk_flags \
    -v web_only="$web_only" \
    -v fmt="$format" \
    -v sre="$service_re" \
    -v preg="$port_re" \
    -v prre="$proto_re" \
    -v prefer_hostname="$prefer_hostname" \
    -v emit_json="$emit_json" \
    -v emit_csv="$emit_csv" \
    -v csv_sep="$field_sep" \
    -v csv_header="$csv_header" \
    -v group_mode="$group_mode" \
    -v stream="$stream" \
    '
    BEGIN { FS="\t"; OFS="\t"; printed_header=0 }
    '"$render_block"'
    {
      ip=$1; host=$2; port=$3; proto=$4; svc=$5; ver=$6; tunnel=$7; cpe=$8; os=$10
      if (svc=="") svc="unknown"
      if (svc !~ sre) next
      if (port !~ preg) next
      if (proto !~ prre) next

      scheme = to_scheme(svc,tunnel)
      target = (prefer_hostname && host!="") ? host : ip
      url=""; if (scheme!="") url = scheme "://" br_ip(target) ":" port
      if (web_only && url=="") next

      if (group_mode=="ip") {
        item = (url!="") ? url : (svc ":" port)
        push_group(ip, item)
      } else {
        out_render(ip,host,port,proto,svc,ver,url,"",cpe,os)
        if (stream) fflush()
      }
    }
    END {
      if (group_mode=="ip") {
        for (h in GROUP) {
          if ('"$emit_json"') {
            n=split(GROUP[h], garr, /\n/)
            printf("{\"ip\":\"%s\",\"items\":[", json_escape(h))
            for (i=1;i<=n;i++){ if (i>1) printf(","); printf("\"%s\"", json_escape(garr[i])) }
            printf("]\n")
          } else if ('"$emit_csv"') {
            if (!printed_header && csv_header) { printf("IP%sITEMS\n", csv_sep); printed_header=1 }
            gsub(/\n/,"|",GROUP[h]); printf("%s%s%s\n", h, csv_sep, GROUP[h])
          } else {
            g=GROUP[h]; gsub(/\n/,", ",g); print h " -> " g
          }
        }
      }
    }
  '
}

# ------------------------- Pre-index (only if asked) -------------------------
services_list=""; ports_list=""
if (( build_index == 1 )); then
  if [[ "$input_type" == "gnmap" ]]; then
    mapfile -t pre < <(
      awk '
        function split_ports_safe(s, outarr,   parts,i,acc,cnt){cnt=0;acc="";split(s, parts, /, /);
          for(i=1;i<=length(parts);i++){ if(acc=="")acc=parts[i]; else acc=acc ", " parts[i];
            split(acc,f,"/"); if(length(f)>=7){ outarr[++cnt]=acc; acc="" }} if(acc!="")outarr[++cnt]=acc; return cnt }
        /^Host:/ && /Ports:/ {
          line=$0; p=index(line,"Ports:"); ports_sub=substr(line,p+6)
          ig=index(ports_sub,"Ignored "); if (ig>0) ports_sub=substr(ports_sub,1,ig-2)
          si2=index(ports_sub,"Service Info:"); if (si2>0) ports_sub=substr(ports_sub,1,si2-2)
          n=split_ports_safe(ports_sub, arr)
          for(i=1;i<=n;i++){ split(arr[i], f, "/"); if(f[2] ~ /^open/){ svc=f[5]; if(svc=="")svc="unknown"; print "SVC\t" svc; print "PRT\t" f[1] } }
        }
      ' "$input_file"
    )
  else
    mapfile -t pre < <(
      xmlstarlet sel -t -m '/nmaprun/host[status/@state="up"]/ports/port[state/@state="open"]' \
        -v 'concat("SVC\t", service/@name)' -n \
        -v 'concat("PRT\t", @portid)' -n \
      "$input_file"
    )
  fi
  if ((${#pre[@]})); then
    services_list="$(printf "%s\n" "${pre[@]}" | awk -F'\t' '$1=="SVC"{print $2}' | sort -u)"
    ports_list="$(printf "%s\n" "${pre[@]}" | awk -F'\t' '$1=="PRT"{print $2}' | sort -n -u)"
  fi
fi

if (( pick_services )) && [[ -n "$services_list" ]]; then
  service_re="$(pick_from_fzf "$services_list")"
fi
if (( pick_ports )) && [[ -n "$ports_list" ]]; then
  port_re="$(pick_from_fzf "$ports_list")"
fi

# ------------------------- Run -------------------------
rendered=""
if [[ "$input_type" == "xml" ]]; then
  rendered="$(parse_xml "$input_file")"
else
  rendered="$(parse_gnmap "$input_file")"
fi

# Postproc (skip in stream mode)
postproc() {
  if (( unique )); then
    if (( sort_output )); then sort -u; else awk '!seen[$0]++'; fi
  else
    if (( sort_output )); then sort; else cat; fi
  fi
}

if (( stream )); then
  # Already printed in-order; nothing to do here
  :
else
  if [[ -z "$rendered" ]]; then
    (( verbose )) && echo "pam-ng: no matches after filters." >&2
    exit 0
  fi
fi

# Output
emit() {
  if [[ -n "$output_file" ]]; then
    if (( print0 )); then printf "%s\0" "$1" | postproc | tee -a "$output_file" >/dev/null
    else printf "%s\n" "$1" | postproc | tee -a "$output_file" >/dev/null
    fi
  else
    if (( print0 )); then printf "%s\0" "$1" | postproc
    else printf "%s\n" "$1" | postproc
    fi
  fi
}
if (( ! stream )); then emit "$rendered"; fi
