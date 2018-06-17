#!/bin/bash
# File              : codius-install.sh
# Author            : N3TC4T <netcat.av@gmail.com>
#Forked Author      : TheRippening <contact@games.com>
# Date              : 16.06.2018
# Last Modified Date: 16.06.2018
# Last Modified By  : TheRippening <contact@zerpgames.com>
# Copyright (c) 2018 N3TC4T <netcat.av@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


#################################################################################################################
# TheRippening (Myself) has removed the colorEcho function and adjusted the script to include some dependancies, 
# typos for SSL certificate integration into nginx and certbot certificate creation.
##############################################################################################################3##
echo '##############################################################################'
echo 'THIS HAS BEEN MODIFIED TO BE A SIMPLER VERSION OF THE GREAT WORK MADE BY N3TC4T <netcat.av@gmail.com>'
echo ' CHANGES INCLUDE: '
echo 'certbot --prefer-challenges > --preferred-challenges'
echo 'ssl_session_cache sha:SSL:10m; > ssl_session_cache shared:SSL:10m; '
echo ' colorEcho > removed '
echo 'nginx dependancy > yum install php-fpm -y'
echo 'Locally saves hyper-bootstrap.sh to disk then runs it locally'
echo 'Prior to running hyper-bootstrap.sh it changes RED, YELLOW, etc colors with the new variable syntax () instead of comments'
echo '##############################################################################'

set -o nounset
set -o errexit
set -eu

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi


if [[ -e /etc/debian_version ]]; then
	OS=debian
elif [[ -e /etc/centos-release || -e /etc/hat-release ]]; then
	OS=centos
elif [[ -e /etc/arch-release ]]; then
	OS=arch
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu ,CentOS or Arch"
	exit
fi

if [[ $OS != centos ]]; then
  echo "Sorry but for now just Centos supported!" 
  exit
fi

clear
echo 'Welcome to codius installer!'
echo
echo "I need to ask you a few questions before starting the setup."
echo "You can leave the default options and just press enter if you are ok with them."
echo


# Server Ip Address
echo "[+] First, provide the IPv4 address of the network interface"
# Autodetect IP address and pre-fill for the user
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
read -p "IP address: " -e -i $IP IP
# If $IP is a private IP address, the server must be behind NAT
if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    echo
    echo "This server is behind NAT. What is the public IPv4 address?"
    read -p "Public IP address: " -e -i  PUBLICIP
fi

# Hostname
echo "[+] What is your Codius hostname?" 
read -p "Hostname: " -e -i codius1.zerpgames.com HOSTNAME
if [[ -z "$HOSTNAME" ]]; then
   printf '%s\n' "No Hostname ente , exiting ..."
   exit 1
fi

# Set hostname 
hostnamectl set-hostname $HOSTNAME


# Wallet secret for moneyd
echo "[+] What is your XRP wallet secret (need for moneyd) ?"
read -p "Wallet Secret: " -e -i SECRET
if [[ -z "$SECRET" ]]; then
   printf '%s\n' "No Secret ente, exiting..."
   exit 1
fi

# Email for certbot
echo "[+] What is your Email address ?"
read -p "Email: " -e -i admin@example.com EMAIL

if [[ -z "$EMAIL" ]]; then
    printf '%s\n' "No Email ente, exiting..."
    exit 1
fi


# Hyperd ==============================================

echo "\n[!] Installing requi packages ...\n" 
sudo yum install -y gcc-c++ make epel-release git wget
echo "\n[!] Installing Hyperd ...\n" 
curl -L https://coiltest.s3.amazonaws.com/upload/latest/hyper-bootstrap.sh > hyper-bootstrap.sh

sed -i -e 's/RED=`tput setaf 1`/RED=(tput setaf 1)/g' hyper-bootstrap.sh 
sed -i -e 's/GREEN=`tput setaf 2`/GREEN=(tput setaf 2)/g' hyper-bootstrap.sh 
sed -i -e 's/YELLOW=`tput setaf 3`/YELLOW=(tput setaf 3)/g' hyper-bootstrap.sh 
sed -i -e 's/BLUE=`tput setaf 4`/BLUE=(tput setaf 4)/g' hyper-bootstrap.sh 
sed -i -e 's/WHITE=`tput setaf 7`/WHITE=(tput setaf 7)/g' hyper-bootstrap.sh 
sed -i -e 's/LIGHT=`tput bold `/LIGHT=(tput bold)/g' hyper-bootstrap.sh 
sed -i -e 's/RESET=`tput sgr0`/RESET=(tput sgr0)/g' hyper-bootstrap.sh 

/bin/bash hyper-bootstrap.sh 

# ============================================== Hyperd

# Moneyd ==============================================

echo "\n[!] Installing Nodejs ...\n" 
curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -
sudo yum install -y nodejs
echo "\n[!] Installing Moneyd ...\n" 
sudo yum install -y https://s3.us-east-2.amazonaws.com/codius-bucket/moneyd-xrp-4.0.0-1.x86_64.rpm || true


# Configuring moneyd and start service
[ -f /root/.moneyd.json ] && mv /root/.moneyd.json /root/.moneyd.json.back

echo "\n[!] Configure Moneyd ...\n" 
echo -ne "$SECRET\n" | /usr/bin/moneyd xrp:configure


if pgrep systemd-journal; then
    systemctl restart moneyd-xrp
else
    /etc/init.d/moneyd-xrp restart
fi

# ============================================== Moneyd


# Codius ==============================================

echo "\n[!] Installing Codius ...\n" 
sudo npm install -g codiusd --unsafe-perm


echo "[Unit]
Description=Codiusd
After=network.target nss-lookup.target
[Service]
ExecStart=/usr/bin/npm start
Environment="DEBUG=*"
Environment="CODIUS_PUBLIC_URI=https://$HOSTNAME"
Environment="CODIUS_XRP_PER_MONTH=10"
WorkingDirectory=/usr/lib/node_modules/codiusd
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=codiusd
User=root
Group=root
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/codiusd.service

if pgrep systemd-journal; then
    systemctl enable codiusd
    systemctl restart codiusd
else
    /etc/init.d/codiusd enable
    /etc/init.d/codiusd restart
fi

# ============================================== Codius

# Subdomain DNS ==============================================
echo
echo "\n[!] Please create two A records on your DNS and press enter to continue : \n" 
echo "$HOSTNAME.    300     IN      A       $IP
*.$HOSTNAME.  300     IN      A       $IP"

read
while true; do
    ping -c 1 $HOSTNAME >/dev/null 2>&1
    if [ $? -ne 0 ] ; then #if ping exits nonzero...
	echo "[!] It's look like the host $HOSTNAME is not avalibale yet , waiting 30s ... " 
    else
	echo "\n[!] Everything looks fine, continuing ... \n" 
	break

    fi
    sleep 30 #check again in SLEEP seconds
done

# ============================================== Subdomain DNS




# CertBOt ==============================================

echo "\n[+] Generating certificate for ${HOSTNAME}\n" 
# certbot stuff
[ -d certbot ] && rm -rf certbot
git clone https://github.com/certbot/certbot
cd certbot
git checkout v0.23.0
./certbot-auto --noninteractive --os-packages-only
./tools/venv.sh > /dev/null
sudo ln -sf `pwd`/venv/bin/certbot /usr/local/bin/certbot
certbot certonly --manual -d "${HOSTNAME}" -d "*.${HOSTNAME}" --agree-tos --email "${EMAIL}" --preferred-challenges dns-01  --server https://acme-v02.api.letsencrypt.org/directory
#certbot --nginx

# ============================================== CertBOt

# Install Nginx dependancy ===========================

yum install php-fpm -y

# ========================Install Nginx dependancy====

# Nginx ==============================================

echo "\n[!] Installing Nginx ...\n" 
# Nginx
sudo yum install -y nginx

if pgrep systemd-journal; then
    systemctl enable nginx
else
    /etc/init.d/nginx enable
fi

if [[ ! -e /etc/nginx/default.d ]]; then
	mkdir /etc/nginx/default.d
fi

echo 'return 301 https://$host$request_uri;' | sudo tee /etc/nginx/default.d/ssl-irect.conf
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048


if [[ ! -e /etc/nginx/conf.d ]]; then
	mkdir /etc/nginx/conf.d
fi

echo "server {
  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/$HOSTNAME/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/$HOSTNAME/privkey.pem;
  ssl_protocols TLSv1.2;
  ssl_prefer_server_ciphers on;
  ssl_dhparam /etc/nginx/dhparam.pem;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
  ssl_ecdh_curve secp384r1;
  ssl_session_timeout 10m;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 1.1.1.1 1.0.0.1 valid=300s;
  resolver_timeout 5s;
  add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload';
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;
  add_header X-XSS-Protection '1; mode=block';
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $$host;
    proxy_set_header X-Forwarded-For $$remote_addr;
  }
}" > /etc/nginx/conf.d/codius.conf


if pgrep systemd-journal; then
    systemctl restart nginx
else
    /etc/init.d/nginx restart
fi

# ============================================== Nginx


echo "\n[!]Congratulations , it's look like Codius installed successfuly!" 
echo "\n[-]You can check your Codius with opening $HOSTNAME/version or by visiting the peers list in https://codius.justmoon.com/peers " 
echo "\n[-]Good luck :)" 
