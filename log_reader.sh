#!/bin/bash 

TELEGRAM_TOKEN=""
NGINX_LOG="/var/log/nginx/access.log"
n=0
YOUR_API_KEY="" #Get your own KEY
function sendTG() {
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=358477256&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}


function read_file() {
	export ip=$(tail -n 1 $NGINX_LOG | awk '{print $1}');
	export time=$(tail -n 1 $NGINX_LOG | awk '{print $4 $5}')
}

function sendTGPQHAZ(){
    curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendmessage" --data "text=${*}&chat_id=958877875&disable_web_page_preview=true&parse_mode=Markdown" > /dev/null
}

function abuseipdb() {
	if [ $n -eq 0 ]; then
		output=$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip}" -d maxAgeInDays=90 -d verbose -H "Key: $YOUR_API_KEY" -H "Accept: application/json")
		whitelist=$( echo $output | jq '.data.isWhitleisted')
		score=$( echo $output | jq '.data.abuseConfidenceScore')
		isp=$( echo $output | jq '.data.isp'| tr "&" " ")
		echo $isp
		countryname=$( echo $output | jq '.data.countryName')
		totalreport= $( echo $output | jq '.data.totalReports')
		lastreport=$( echo $output | jq '.data.lastReportedAt')
		ip1=$ip
		if [ $score -gt 1 ]; then
			block_ip $ip
			sendTG "Successfully Blocked! %0AIP: $ip %0ACountry: $countryname %0AAbusescore: $score %0ALast Report: $lastreport %0ATotal Reports: $totalreport"
			sendTGPQHAZ "Successfully Blocked! %0AIP: $ip %0ACountry: $countryname %0AAbusescore: $score %0ALast Report: $lastreport %0ATotal Reports: $totalreport"
		else
			sendTG "IP: $ip %0ATime: $time %0AWhitelist: $whitelist %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport   "
		fi
		$n=$((n++))
	else
	if [ $ip != $ip1 ]; then
		output=$(curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip}" -d maxAgeInDays=90 -d verbose -H "Key: $YOUR_API_KEY" -H "Accept: application/json")
		whitelist=$( echo $output | jq '.data.isWhitleisted')
		score=$( echo $output | jq '.data.abuseConfidenceScore')
		isp=$( echo $output | jq '.data.isp'| tr "&" " ")
		countryname=$( echo $output | jq '.data.countryName')
		totalreport= $( echo $output | jq '.data.totalReports')
		lastreport=$( echo $output | jq '.data.lastReportedAt')
		ip1=$ip
		if [ $score -gt 1 ]; then
			block_ip $ip
			sendTG "Successfully Blocked! %0AIP: $ip %0ACountry: $countryname %0AAbusescore: $score %0ALast Report: $lastreport"
		else
			sendTG "IP: $ip %0ATime: $time %0AWhitelist: $whitelist %0AAbusescore: $score %0AISP: $isp %0ACountry: $countryname %0ATotal Reports: $totalreport %0ALast Report: $lastreport   "
		fi
	fi
	fi
}

########################################################
#
# MAIN
#
########################################################

while true; do
read_file
abuseipdb
done
