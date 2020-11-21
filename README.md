# Telegram-IP-Check-Bot
This script will parse NGINX- and dmesg-logs and checks the ip addresses found there using the AbuseIPDB and Alienvault-API to see if it is a malicious ip and blocks it if necessary.


## Quick start for Debian/Ubuntu based installations
1. wget https://raw.githubusercontent.com/Billaids/Telegram-IP-Check-Bot/master/check_bot.sh
2. chmod +x check_bot.sh
3. Enable iptables logging: 
```
  sudo iptables -A INPUT -j LOG
  sudo iptables -A FORWARD -j LOG
  sudo ip6tables -A INPUT -j LOG
  sudo ip6tables -A FORWARD -j LOG
```
4. Install jq
```
  sudo apt-get install jq
```
5. Get [Telegram Bot API-Key](https://tutorials.botsfloor.com/creating-a-bot-using-the-telegram-bot-api-5d3caed3266d) and your [CHATID](https://telegram.me/get_id_bot) 
6. Get an [AbuseIPDB](https://docs.abuseipdb.com/#introduction) and [Alienvault](https://otx.alienvault.com/api) API-Key
7. fill in your MAC-Address from ethernet adapter and server ip etc.
8. run bot, if you filled in empty vars.

## WARNING!
It might be possible that this script blocks ip-addresses that are actually harmless. It checks for the abusescore from AbuseIPDB and Alienvault (Threadscore), which can result in false-positives.

## Screenshot
 
<img src="https://github.com/Billaids/Telegram-IP-Check-Bot/blob/master/portscan_notification.jpg" width="400" />

## Contributors
@KEN 
@uberhahn
