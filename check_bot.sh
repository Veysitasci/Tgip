#!/bin/bash

TELEGRAM_TOKEN=""
NGINX_LOG="/var/log/nginx/access.log"
ABUSEIPDB_API_KEY="" # ABUSEIPBDP-KEY
IP_LOG="/root/ips.txt"
ALIENVAULT_API_KEY="" #Alienvault-KEY
URL=""
CHAT_ID=""
CHAT_ID_2=""
REPORT_WEB_ATTACK="19,20,21"
REPORT_PORT_SCAN="14"
KERNEL_LOG="/var/log/kern.log"
SERVER_IP=""
SERVER_MAC=""
HOST_NAME=""
second_size_nginx=0
OWN_IP=""
LOG_DMESG=""

function send_tg() {
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=${CHAT_ID}&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}


function read_file_dmesg() {
    dmesg -TS >> $LOG_DMESG
    mapfile -t port_scan_ip< <(cat $LOG_DMESG |  grep -v $OWN_IP)

}

function read_file_nginx(){
    mapfile -t ip < <(tail -n 100 $NGINX_LOG | cut -d " "  -f1 | grep -v $OWN_IP) #change here amount of ip's, cut is faster than awk
}

function send_tg_2(){
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=${CHAT_ID_2}&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}

function alienvault(){
    alien_output=$(curl https://otx.alienvault.com/api/v1/indicators/IPv4/"${*}"/reputation -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY" )
    alien_score=$( echo "$alien_output" | jq '.reputation.threat_score' | sed 's/null/0/g'| sed 's/\r//g')
    malicious_host=$( echo "$alien_output" | jq '.reputation.counts."Malicious Host"' | sed 's/null/0/g' | sed 's/1/MALICIOUS HOST/g' | sed 's/\r//g' )
}

function reportabuseipdb(){
    report_ip=$(curl https://api.abuseipdb.com/api/v2/report  --data-urlencode "ip=${1}"  -d categories=${2} --data-urlencode "comment=${3}" -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
    report_score=$(echo "$report_ip" | jq '.data.abuseConfidenceScore' | sed 's/null/0/g' | sed 's/\r//g')
}

function send_abuseipbdb_request(){
    ip_check="$1"
    alienvault "$1"
    output=$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$1" -d maxAgeInDays=90 -d verbose -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
    whitelist=$( echo "$output" | jq '.data.isWhitleisted' | sed 's/null/0/g' | sed 's/\r//g')
    score=$( echo "$output" | jq '.data.abuseConfidenceScore' | sed 's/null/0/g' | sed 's/\r//g')
    isp=$( echo "$output" | jq '.data.isp'| (sed 's/&/ /g' || sed 's/null/ /g' | sed 's/\r//g')) #http api cant handle &
    countryname=$( echo "$output" | jq '.data.countryName' | sed 's/null/ /g'| sed 's/\r//g')
    totalreport=$( echo "$output" | jq '.data.totalReports' | sed 's/null/0/g'| sed 's/\r//g')
    lastreport=$( echo "$output" | jq '.data.lastReportedAt'| sed 's/null/0/g'| sed 's/\r//g')
    if [[ $3 != "psad" ]]; then
        log_message=$(cat $NGINX_LOG | grep "$1" | awk '{print $0}' | tail -n 3 | sed "s/https:\/\/${URL}//g"| sed "s/http:\/\/${URL}//g" | sed 's/\r//g' )
        nginx_time=$(echo $log_message | cut -d " " -f4)
        if [ "$score" -gt 1 ] || [ "$alien_score" -gt 0 ] || [ "$totalreport" -gt 0 ] ; then
            block_message="Successfully Blocked! %0AIP: $1 %0ATime: $nginx_time %0ACountry: $countryname %0AAbusescore: $report_score %0AISP: $isp %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $log_message "
            block_ip "$1"
            reportabuseipdb "$1" "$2" "$log_message"
            sleep 1.5 #Tg needs 0.5sec gap between 2 messages
            send_tg "$block_message"
            sleep 1.5
            send_tg_2 "$block_message"
        else
            message="%0AIP: $1 %0ATime: $nginx_time %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $log_message"
            sleep 1.5
            send_tg "$message"
            sleep 1.5
            send_tg_2 "$message"
        fi
    else
        scanned_ports=$5
        log_message=$(echo $6 | sed "s/$SERVER_IP/MYSERVERIP/g" | sed "s/$SERVER_MAC/SERVERMAC/g" | sed "s/$HOST_NAME//g")
        port_scan_time=$4
        report_message=$(echo "$log_message Ports: $scanned_ports")
        if [ "$score" -gt 1 ] || [ "$alien_score" -gt 0 ] || [ "$totalreport" -gt 0 ] ; then
            block_message="PORTSCAN: %0ASuccessfully Blocked! %0AIP: $1 %0APorts: $scanned_ports %0ATime: $port_scan_time %0ACountry: $countryname %0AAbusescore: $report_score %0AISP: $isp %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $log_message "
            block_ip "$1"
            reportabuseipdb "$1" "$2" "$report_message"
            sleep 1.5 #Tg needs 0.5sec gap between 2 messages
            send_tg "$block_message"
            sleep 1.5
            send_tg_2 "$block_message"
        else
            message="PORTSCAN: %0AIP: $1 %0APorts: $scanned_ports %0ATime: $port_scan_time %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host %0A%0AMessage: $log_message"
            sleep 0.5
            send_tg "$message"
            sleep 1
            send_tg_2 "$message"
        fi
    fi
    echo "$1" >> $IP_LOG
}

function check_nginx_log() {
    for ((i=0;i<=${#ip[@]};i++));do
        if [[ -z ${ip[i]} ]]; then
            break
        fi
        current_ip=${ip[i]}
        nginx_ip=$(grep $current_ip $IP_LOG | tail -n 1)
        if [ -z $nginx_ip ]; then
            send_abuseipbdb_request "$current_ip" "$REPORT_WEB_ATTACK" "nginx"
        fi
    done
}

function check_port_scan(){
    for ((x=0;x<=${#port_scan_ip[@]};x++));do
        current_ip=$(echo ${port_scan_ip[x]} | egrep -o "SRC=+[0-9]*.[0-9]*.[0-9]*.[0-9]*" | sed 's/SRC=//' )
        if [[ -z $current_ip ]]; then
            break
        fi
        ip_check=$(grep $current_ip $IP_LOG | tail -n 1)
        if [ -z $ip_check ]; then
            current_time=$(echo ${port_scan_ip[x]} | egrep -o  "[A-Z]+[a-z]*[[:space:]]+[A-Z]..[[:space:]][0-9].[[:space:]][0-9]*:[0-9]*:[0-9]*[[:space:]][0-9]*" ) # TODO: REFACTOR
            current_port=$(echo ${port_scan_ip[x]} | egrep -o "DPT=+[0-9]*" | sed 's/DPT=//')
            if [[ -z $current_port ]]; then
                current_port=$(echo ${port_scan_ip[x]} | egrep -o "PROTO=[A-Z]*" | sed 's/PROTO=//')
            fi
            if [[ -n $current_ip ]] && [[ -n $current_time ]]; then
                send_abuseipbdb_request "$current_ip" "$REPORT_PORT_SCAN" "psad" "$current_time" "$current_port" "${port_scan_ip[x]}"
            fi
        fi
    done
    if [ $x -gt 3000 ]; then
        rm -f $LOG_DMESG
    fi
}

function set_vars_nginx(){
    set port_scan_ip
}

function unset_vars_nginx(){
    unset ip
}

function set_vars_dmesg(){
    set ip
}

function unset_vars_dmesg(){
    unset port_scan_ip
}

########################################################
#
# MAIN
#
########################################################

if ! [[ -w $IP_LOG ]]; then #TODO: Refactor with for-loop
    touch $IP_LOG
    echo "127.0.0.1" >> $IP_LOG
    echo "127.0.0.53" >> $IP_LOG
    echo "::1" >> $IP_LOG
    echo "8.8.8.8" >> $IP_LOG #Google DNS
    echo "1.1.1.1" >> $IP_LOG #Cloudflare DNS
    echo "8.8.4.4" >> $IP_LOG #Google DNS
    echo "213.133.98.98" >> $IP_LOG #Hetzner DNS
    echo "213.133.99.99" >> $IP_LOG
    echo "213.133.100.100" >> $IP_LOG
fi

while true; do
    dmesg -TS >> $LOG_DMESG
    first_size_nginx=$(du -b $NGINX_LOG | cut -f 1)
    sleep 3
    if [[ $first_size_nginx != $second_size_nginx ]]; then
        set_vars_nginx
        read_file_nginx
        check_nginx_log
        unset_vars_nginx
        second_size_nginx=$(du -b $NGINX_LOG | cut -f 1)
    fi
    set_vars_dmesg
    read_file_dmesg
    check_port_scan
    unset_vars_dmesg
done
