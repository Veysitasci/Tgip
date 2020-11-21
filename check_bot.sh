#!/bin/bash

source $(pwd)/config.sh

second_size_nginx=0
set port_scan_ip
set ip

function send_tg() {
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=${CHAT_ID}&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}


function read_file_dmesg() {
    dmesg -TS >> $LOG_DMESG
    mapfile -t port_scan_ip< <(cat $IPS_FILTERED)
}

function read_file_nginx(){
    cat $NGINX_LOG | cut -d " " -f1 > $IP_RAW_NGINX
    awk 'FNR==NR{a[$0]=1;next}!($0 in a)' $IP_LOG $IP_RAW_NGINX | sort| uniq > $IPS_FILTERED_NGINX # https://stackoverflow.com/questions/4717250/extracting-unique-values-between-2-sets-files
    mapfile -t ip < <(cat $IPS_FILTERED_NGINX)
}

function sort_ips(){
    cat $LOG_DMESG | egrep -o "SRC=+[0-9]*.[0-9]*.[0-9]*.[0-9]*" | sed 's/SRC=//' > $IP_RAW
    awk 'FNR==NR{a[$0]=1;next}!($0 in a)' $IP_LOG $IP_RAW | sort| uniq > $IPS_FILTERED # https://stackoverflow.com/questions/4717250/extracting-unique-values-between-2-sets-files
}

function send_tg_2(){
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=${CHAT_ID_2}&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}

function alienvault(){
    alien_output=$(curl https://otx.alienvault.com/api/v1/indicators/IPv4/"${*}"/reputation \
        -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY" )
    alien_score=$( echo "$alien_output" | jq '.reputation.threat_score' | (sed 's/null/0/g'; sed 's/\r//g'))
    malicious_host=$( echo "$alien_output" | jq '.reputation.counts."Malicious Host"' | (sed 's/null/0/g' ; sed 's/1/MALICIOUS HOST/g' ; sed 's/\r//g'))
}

function reportabuseipdb(){
    report_ip=$(curl https://api.abuseipdb.com/api/v2/report \
            --data-urlencode "ip=${1}" \
            -d categories=${2} \
            --data-urlencode "comment=${3}" \
            -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json")
    report_score=$(echo "$report_ip" | jq '.data.abuseConfidenceScore' | (sed 's/null/0/g' ; sed 's/\r//g'))
}

function send_abuseipbdb_request(){

    ip_check="$1"
    alienvault "$1"
    output=$(curl -G https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=$1"\
            -d maxAgeInDays=90 -d verbose \
            -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json")
    whitelist=$( echo "$output" | jq '.data.isWhitleisted' | (sed 's/null/0/g' ; sed 's/\r//g'))
    score=$( echo "$output" | jq '.data.abuseConfidenceScore' | ( sed 's/null/0/g' ; sed 's/\r//g'))
    isp=$( echo "$output" | jq '.data.isp'| (sed 's/&/ /g' ; sed 's/null/ /g' ; sed 's/\r//g')) #http api cant handle &
    countryname=$( echo "$output" | jq '.data.countryName' | (sed 's/null/ /g' ; sed 's/\r//g'))
    totalreport=$( echo "$output" | jq '.data.totalReports' | (sed 's/null/0/g' ; sed 's/\r//g'))
    lastreport=$( echo "$output" | jq '.data.lastReportedAt'| (sed 's/null/0/g' ; sed 's/\r//g'))

    if [[ $3 != "portscan" ]]; then # the following part is only for nginx logs
        log_message=$(cat $NGINX_LOG | grep "$1" | awk '{print $0}' | tail -n 3 | (sed "s/https:\/\/${URL}//g" ; sed "s/http:\/\/${URL}//g" ; sed 's/\r//g')) # cut the whole line from nginx log and remove your url abuseipdb reports
        nginx_time=$(echo $log_message | cut -d " " -f4) # cut the time from nginx log
        if [ "$score" -gt 1 ] || [ "$alien_score" -gt 0 ] || [ "$totalreport" -gt 0 ] ; then  # bad ip check with vars from api response. $score = Abusescore (AbuseIPDB) $totalreport=Amount of Reports (AbuseIPDB) $alien_score=Abusescore from Alienvault TODO: Add Countryfilter
            #  API Response vars from AbuseIPDB and Alienvault, ip will be blocked if it has a bad reputation
            block_message="%0ASuccessfully Blocked! %0AIP: $1 \
            %0ATime: $nginx_time \
            %0ACountry: $countryname \
            %0AAbusescore: $report_score \
            %0AISP: $isp \
            %0ALast Report: $lastreport%0A \
            %0A############# \
            %0AAlienvault Results:%0A \
            %0AThreat Score: $alien_score \
            %0AMalicious: $malicious_host \
            %0A%0AMessage: $log_message "
            iptables -A INPUT -s "$1" -j DROP #block it in firewall
            reportabuseipdb "$1" "$2" "$log_message"
            sleep 1 #Tg needs 0.5sec gap between 2 messages
            send_tg "$block_message"
            sleep 1
            send_tg_2 "$block_message"
        else # this condition is true, if its an ip without a bad reputation, but it could be a false positive!
            message="%0AIP: $1 \
		    %0ATime: $nginx_time \
		    %0AAbusescore: $score \
		    %0AISP: $isp \
		    %0ACountry: $countryname \
		    %0ATotal Reports: $totalreport \
		    %0ALast Report: $lastreport%0A \
		    %0A#############%0AAlienvault Results:%0A \
		    %0AThreat Score: $alien_score \
		    %0AMalicious: $malicious_host \
		    %0A%0AMessage: $log_message"
            sleep 1
            send_tg "$message"
            sleep 1
            send_tg_2 "$message"
        fi
    else # PORTSCAN PART !
        scanned_ports=$5
        log_message=$(grep "$1" $LOG_DMESG | tail -1 | (sed "s/$SERVER_IP/MYSERVERIP/g" | sed "s/$SERVER_MAC/SERVERMAC/g" ; sed "s/$HOST_NAME//g")) # cut the whole line from dmesg and remove hostname and server mac
        port_scan_time=$4
        report_message=$(echo "$log_message Ports: $scanned_ports")
        if [ "$score" -gt 1 ] || [ "$alien_score" -gt 0 ] || [ "$totalreport" -gt 0 ] ; then # bad ip check with vars from api response. $score = Abusescore (AbuseIPDB) $totalreport=Amount of Reports (AbuseIPDB) $alien_score=Abusescore from Alienvault  TODO: Add Countryfilter
            block_message="PORTSCAN: %0ASuccessfully Blocked!\
		    %0AIP: $1 \
		    %0APorts: $scanned_ports \
		    %0ATime: $port_scan_time \
		    %0ACountry: $countryname \
		    %0AAbusescore: $report_score \
		    %0AISP: $isp \
		    %0ALast Report: $lastreport%0A \
		    %0A#############%0AAlienvault Results:%0A \
		    %0AThreat Score: $alien_score \
		    %0AMalicious: $malicious_host \
		    %0A%0AMessage: $log_message "
            iptables -A INPUT -s "$1" -j DROP
            reportabuseipdb "$1" "$2" "$report_message"
            sleep 1 #Tg needs 0.5sec gap between 2 messages
            send_tg "$block_message"
            sleep 1
            send_tg_2 "$block_message"
        else # this condition is true, if its an ip without a bad reputation, but it could be a false positive!
            message="PORTSCAN: \
		    %0AIP: $1 \
		    %0APorts: $scanned_ports \
		    %0ATime: $port_scan_time \
		    %0AAbusescore: $score \
		    %0AISP: $isp \
		    %0ACountry: $countryname \
		    %0ATotal Reports: $totalreport \
		    %0ALast Report: $lastreport%0A \
		    %0A#############%0AAlienvault Results:%0A \
		    %0AThreat Score: $alien_score \
		    %0AMalicious: $malicious_host \
		    %0A%0AMessage: $log_message"
            sleep 1
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
        nginx_ip=$(grep "$current_ip" $IP_LOG | tail -n 1)
        if [ -z $nginx_ip ]; then
            send_abuseipbdb_request "$current_ip" "$REPORT_WEB_ATTACK" "nginx"
        fi
    done
}

function check_port_scan(){
    for ((x=0;x<=${#port_scan_ip[@]};x++));do
        current_ip="${port_scan_ip[x]}"
        if [[ -z $current_ip ]]; then
            break
        fi
        current_time=$(cat $LOG_DMESG | grep "${port_scan_ip[x]}" | tail -1 | egrep -o  "[A-Z]+[a-z]*[[:space:]]+[A-Z]..[[:space:]][0-9].[[:space:]][0-9]*:[0-9]*:[0-9]*[[:space:]][0-9]*" )
        current_port=$(cat $LOG_DMESG | grep "${port_scan_ip[x]}" | tail -1 | egrep -o "DPT=+[0-9]*" | sed 's/DPT=//')
        if [[ -z $current_port ]]; then
            current_port=$(cat $LOG_DMESG | grep "${port_scan_ip[x]}" | tail -1 | egrep -o "PROTO=[A-Z]*" | sed 's/PROTO=//')
        fi
        if [[ -n $current_ip ]] && [[ -n $current_time ]]; then
            send_abuseipbdb_request "$current_ip" "$REPORT_PORT_SCAN" "portscan" "$current_time" "$current_port"
        fi
    done
    rm $LOG_DMESG
}

function has_log_grown(){ #Author @KEN
    current_size_nginx=$(du -b $NGINX_LOG | cut -f 1)
    if [[ ( $first_size_nginx -lt  $current_size_nginx ) ]]
    then
        first_size_nginx=$current_size_nginx
        return 0
    fi
    return 1
}

########################################################
#
# MAIN
#
########################################################

if ! [[ -w $IP_LOG ]]; then
    touch $IP_LOG
    for i in "127.0.0.1" "127.0.0.53" "::1" "8.8.8.8" "1.1.1.1" "8.8.4.4" "213.133.98.98" "213.133.99.99" "213.133.100.100" "149.154.167.220" "$SERVER_IP" # 149.154.167.220  api.telegram.org
    do
        echo "$i" >> $IP_LOG
    done
fi

while true; do
    dmesg -TS >> $LOG_DMESG
    sleep 3
    if has_log_grown; then
        read_file_nginx
        check_nginx_log
    fi
    sort_ips
    read_file_dmesg
    check_port_scan
done
