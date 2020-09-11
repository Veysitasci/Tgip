#!/bin/bash 

TELEGRAM_TOKEN=""
NGINX_LOG="/var/log/nginx/access.log"
YOUR_API_KEY="" #Get your own ABUSEIPBDP-KEY
IP_LOG="/root/ips.txt"
ALIENVAULT_API_KEY="" #Get your own ALIENVAULT-KEY
URL=""

function sendTG() {
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=358477256&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}


function read_file() {
    mapfile -t ip < <(tail -n 30 $NGINX_LOG | awk '{print $1}'); #change here amount of ip's
    mapfile -t time< <( tail -n 30 $NGINX_LOG| awk '{print $4 $5}') #same number as ip's
}

function sendTGPQHAZ(){
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=958877875&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}

function alienvault(){
    alien_output=$(curl https://otx.alienvault.com/api/v1/indicators/IPv4/"${*}"/reputation -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY")
    alien_score=$( echo "$alien_output" | jq '.reputation.threat_score' | sed 's/null/0/g')
    malicious_host=$( echo "$alien_output" | jq '.reputation.counts."Malicious Host"' | (sed 's/null/0/g' || sed 's/1/MALICIOUS HOST/g'))
}

function reportAbuseipdb(){
    message=$(grep "${*}" $NGINX_LOG | awk '{print $0}' | (sed 's/"https:\/\/${URL}"//g'|| sed's/"http:\/\/${URL}"//g'))
    report_ip=$(curl https://api.abuseipdb.com/api/v2/report  --data-urlencode "ip=${*}"  -d categories=19,20,21 --data-urlencode "comment=${message}" -H "Key: $YOUR_API_KEY" -H "Accept: application/json")
    report_score=$(echo "$report_ip" | jq '.data.abuseConfidenceScore' | sed 's/null/0/g')
}

function abuseipdb() {
    for ((i=0;i<=${#ip[@]};i++));do
        ip_check=$(grep "${ip[i]}" $IP_LOG | tail -n 1)
        if [ -z $ip_check ]; then
            ip_check=${ip[i]}
            alienvault "${ip[i]}"
            output=$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip[i]}" -d maxAgeInDays=90 -d verbose -H "Key: $YOUR_API_KEY" -H "Accept: application/json")
            whitelist=$( echo "$output" | jq '.data.isWhitleisted' | sed 's/null/0/g')
            score=$( echo "$output" | jq '.data.abuseConfidenceScore' | sed 's/null/0/g')
            isp=$( echo "$output" | jq '.data.isp'| (sed 's/&/ /g' || sed 's/null/ /g')) #http api cant handle &
            countryname=$( echo "$output" | jq '.data.countryName' | sed 's/null/ /g')
            totalreport=$( echo "$output" | jq '.data.totalReports' | sed 's/null/0/g')
            lastreport=$( echo "$output" | jq '.data.lastReportedAt'| sed 's/null/0/g')
	    nginx_message=$(cat $NGINX_LOG | grep ${ip[i]} | awk '{print $0}' | tail -n 3)
            block_message="Successfully Blocked! %0AIP: ${ip[i]} %0ATime: ${time[i]} %0ACountry: $countryname %0AAbusescore: $report_score %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $nginx_message "
            message="IP: ${ip[i]} %0ATime: ${time[i]} %0AWhitelist: $whitelist %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $nginx_message"
            echo "${ip[i]}" >> $IP_LOG
            if [ "$score" -gt 1 ] || [ "$alien_score" -gt 0 ] || [ "$totalreport" -gt 0 ] ; then
                block_ip ${ip[i]}
                reportAbuseipdb ${ip[i]}
                sleep 2 #Tg needs 0.5sec gap between 2 messages
		sendTG "$block_message"
                sleep 2
                sendTGPQHAZ "$block_message"
            else
                sleep 2
		sendTG "$message"
                sleep 2
                sendTGPQHAZ "$message"
            fi
        fi
    done
}

########################################################
#
# MAIN
#
########################################################

if ! [[ -w $IP_LOG ]]; then
    touch $IP_LOG
    echo "127.0.0.1" >> $IP_LOG
    echo "::1" >> $IP_LOG
fi
while true; do
    first_size=$(du -b $NGINX_LOG | cut -f 1)
    sleep 3
    second_size=$(du -b $NGINX_LOG | cut -f 1)
    if [[ $first_size != $second_size ]]; then
        read_file
        abuseipdb
    fi
done
