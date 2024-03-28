#!/bin/bash

log() {
    local status=$1
    local cmd=$2
    local message=$3
    local datetime=$(date '+%Y-%m-%dT%H:%M:%S.%6N%:z')
    local user=$(whoami)
    echo "${datetime} ${status} (${user}) CMD (${cmd}) MSG (${message})"
}

urls=(
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
  "https://malware-filter.gitlab.io/phishing-filter/phishing-filter-agh.txt"
  "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
  "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad-pc.txt"
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
)

failed_urls=()
failed_files=()

for index in "${!urls[@]}"; do
    url=${urls[$index]}
    file=$(expr $index + 1)
    if curl --connect-timeout 5 -m 60 --ipv4 -kfsSLo "$file" "$url"; then
        log "INFO" "curl" "Downloaded successfully: $url"
    else
        log "ERROR" "curl" "Failed to download: $url"
        failed_urls+=("$url")
        failed_files+=("$file")
        if ! curl --connect-timeout 5 -m 60 --ipv4 -kfsSLo "$file" "$url"; then
            log "ERROR" "curl" "Second attempt failed: $url"
        else
            log "INFO" "curl" "Second attempt succeeded: $url"
            unset 'failed_urls[${#failed_urls[@]}-1]'
            unset 'failed_files[${#failed_files[@]}-1]'
        fi
    fi
done

if [ ${#failed_urls[@]} -ne 0 ]; then
    for failed_url in "${failed_urls[@]}"; do
        log "ERROR" "curl" "Failed to download: $failed_url"
    done
    exit 1
fi

grep -vhE '^(# |!)' 1 2 3 4 5 6 | sort -u > a
awk '!/^# / && !/^!/' 1 2 3 4 5 6 | sort -u > b

sha256_a=$(sha256sum a | cut -d ' ' -f 1)
sha256_b=$(sha256sum b | cut -d ' ' -f 1)

if [[ $sha256_a != $sha256_b ]]; then
    log "ERROR" "sha256sum" "The SHA256 hashes of the files 'a' and 'b' do not match."
    exit 1
else
    mv a filter.txt
    log "INFO" "mv" "'a' file renamed to 'filter.txt'"
fi

exit 0