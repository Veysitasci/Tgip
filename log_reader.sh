#!/bin/bash 

TELEGRAM_TOKEN=""
NGINX_LOG="/var/log/nginx/access.log"
YOUR_API_KEY="" #Get your own ABUSEIPBDP-KEY
IP_LOG="/root/ips.txt"
ALIENVAULT_API_KEY="" #Get your own ALIENVAULT-KEY

function sendTG() {
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=358477256&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}


function read_file() {
	mapfile -t ip < <(tail -n 20 $NGINX_LOG | awk '{print $1}'); #change here amount ips
	mapfile -t time< <(tail -n 20 $NGINX_LOG | awk '{print $4 $5}') #same number as ips
}

function sendTGPQHAZ(){
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=958877875&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}

function alienvault(){
	alien_output=$(curl https://otx.alienvault.com/api/v1/indicators/IPv4/${*}/reputation -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY")
	alien_score=$( echo $alien_output | jq '.reputation.threat_score')
	malicious_host=$( echo $alien_output | jq '.reputation.counts."Malicious Host"' | sed 's/1/MALICIOUS HOST/g')
}

function abuseipdb() {
	for ((i=0;i<${#ip[@]};i++));do
		ip_check=$(grep $ip $IP_LOG | tail -n 1)
		if ! [ -z $ip_check ]; then
			ip_check=${ip[i]}
		else
			if  [[ "${ip[i]}" =~ $ip_check ]]; then
				alienvault ${ip[i]}
				output=$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip[i]}" -d maxAgeInDays=90 -d verbose -H "Key: $YOUR_API_KEY" -H "Accept: application/json")
				whitelist=$( echo $output | jq '.data.isWhitleisted')
				score=$( echo $output | jq '.data.abuseConfidenceScore')
				isp=$( echo $output | jq '.data.isp'| tr "&" " ")
				countryname=$( echo $output | jq '.data.countryName')
				totalreport= $( echo $output | jq '.data.totalReports')
				lastreport=$( echo $output | jq '.data.lastReportedAt')
				echo ${ip[i]} >> $IP_LOG
					if [ $score -gt 1 ] || [ $alien_score -gt 0 ] ; then
						block_ip ${ip[i]}
						sendTG "Successfully Blocked! %0AIP: ${ip[i]} %0ATime: ${time[i]} %0ACountry: $countryname %0AAbusescore: $score %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host "
						sleep 2
						sendTGPQHAZ "Successfully Blocked! %0AIP: ${ip[i]} %0ATime: ${time[i]} %0ACountry: $countryname %0AAbusescore: $score %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0a %0AThreat Score: $alien_score %0AMalicious: $malicious_host "
					else
						sendTG "IP: ${ip[i]} %0ATime: ${time[i]} %0AWhitelist: $whitelist %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport%0A %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host "
						sleep 2
						sendTGPQHAZ "IP: ${ip[i]} %0ATime: ${time[i]} %0AWhitelist: $whitelist %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport %0A#############%0AAlienvault Results:%0A %0AThreat Score: $alien_score %0AMalicious: $malicious_host "
					fi
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
fi
while true; do
first_size=$(du -b /var/log/nginx/access.log | cut -f 1)
sleep 0.5 
second_size=$(du -b /var/log/nginx/access.log | cut -f 1) 
if [[ $first_size != $second_size ]]; then
	read_file
	abuseipdb
fi
done
