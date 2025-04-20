#!/bin/bash

#./pamng
#Parsed Address Mapper - Next Generation

export FZF_DEFAULT_OPTS="--height=10 --reverse"

formats=(
    "IP"
    "SERVICE"
    "SERVICE: VERSION"
    "SERVICE://IP:PORT"
    "IP:PORT"
    "SERVICE, IP, PORT"
)

usage() {
    echo "Usage: $0 <input_file> [-o output_file] [--web] [-f format (IP, PORT, SERVICE, VERSION)]"
    exit 1
}

webParse() {
    results=$(awk '/Ports:/ {for (i=5; i<=NF; i++) {split($i, a, "/"); if (a[2] ~ /open/ && a[5] ~ /(http|ssl\/http|https)/) print (a[5] ~ /(https|ssl\/http)/ ? "https" : "http") "://" $2 ":" a[1]}}' $input_file)
    if [[ -n "$output_file" ]]; then
        echo "$results" | tee -a "$output_file"
    else
        echo "$results"
    fi
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            output_file="$2"
            shift 2
            ;;
        --web)
            web_filter=1
            shift
            ;;
        -f|--format)
            output_format="$2"
            shift 2
            ;;
        *)
            if [[ -z "$input_file" ]]; then
                input_file="$1"
            else
                echo "Unknown argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

# Check if the input file was provided
if [[ -z "$input_file" ]]; then
    echo "Error: Input file is required."
    usage
fi

if [[ $web_filter ]]; then
    webParse
fi

pas=$(awk '/Ports:/ {for (i=5; i<=NF; i++) {split($i, f, "/"); if (f[2] ~ /open/) {if (f[1] != "") print f[1]; if (f[5] != "") print f[5];}}}' $input_file | sort -n | uniq | sed 's/^[[:space:]]*//')

# Get service filter from user
services_filter=$(echo "$pas" | fzf --multi --prompt="Select services to filter: " | sed 's/^/^/; s/$/$/;' | sed ':a;N;$!ba;s/\n/|/g')

# Get output format choice
if [[ -z "$output_format" ]]; then
    output_format=$(printf "%s\n" "${formats[@]}" | fzf --prompt="Select output format: ")
fi

results=$(awk -v t="$services_filter" -v fmt="$output_format" '
/Ports:/ {
    for (i=5; i<=NF; i++) {
        split($i, a, "/");
        if (a[2] ~ /open/ && ($2 ~ t || a[5] ~ t)) {
            out = fmt
            gsub("IP", $2, out)
            gsub("SERVICE", a[5], out)
            gsub("VERSION", a[7], out)
            gsub("PORT", a[1], out)
            print out
        }
    }
}' $input_file)

if [[ -n "$output_file" ]]; then
    echo "$results" | tee -a "$output_file"
else
    echo "$results"
fi