#/bin/bash
#Show primary IP & FQDN
clear
echo "******************************************************************"
echo "* Your IP address:	" $(ifconfig | awk '/inet addr/{print substr($2,6)}'| head -n 1)
echo "* Your FQDN:		" $(hostname -A)
echo "* Your System:		" $(cat /etc/issue.net)
echo "******************************************************************"

workingdir=$(pwd)
if [[ ! $EUID -eq 0 ]]; then
    exec sudo $0 $@ || echo "Server installation must be run as root user"
    exit 1 # Fail Sudo
fi

#Ask some info
echo "Enter Docs Server IP or FQDN:"
read eip
echo "Create credentials for web access:"
read -p 'Username: ' nginxUsername
#Hide password -s
while true; do
    read -sp 'Password: ' passvar1
    echo
    read -sp 'Verify Password: ' passvar2
    echo
    [ "$passvar1" == "$passvar2" ] && break
    echo "Passwords do not match..."
done

#Ask ftp info
echo "Create credentials for SFPT access:"
read -p 'Username: ' ftpUsername
#Hide password -s
while true; do
    read -sp 'Password: ' ftppass1
    echo
    read -sp 'Verify Password: ' ftppass2
    echo
    [ "$ftppass1" == "$ftppass2" ] && break
    echo "Passwords do not match..."
done

#Update System
sudo apt-get update
sudo apt-get upgrade -y

#Trust self-signed cert by IP as CA
#insert after by name
sed -i "/ v3_ca /a subjectAltName = IP: $eip" /etc/ssl/openssl.cnf
#insert after by line number
# sed -i '226s/.*/subjectAltName = IP: '"$eip"'/' /etc/ssl/openssl.cnf
#Generate SSL Certificates
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private
cd /etc/pki/tls; sudo openssl req -subj '/CN='$eip'/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/Sphinx.key -out certs/Sphinx.crt

#NGINX SSL Reverse Proxy
sudo apt-get -y install nginx apache2-utils
sudo touch /etc/nginx/htpasswd.users
htpasswd -b -c /etc/nginx/htpasswd.users $nginxUsername $passvar1
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/backup_default
cat <<EOC | sudo su
cat <<EOT > /etc/nginx/sites-available/default
server {
        listen 80;
        server_name $eip;
        return 301 https://\\\$server_name\\\$request_uri;
}
server {
        listen 443 default ssl;
        ssl_certificate /etc/pki/tls/certs/Sphinx.crt;
        ssl_certificate_key /etc/pki/tls/private/Sphinx.key;
        ssl_session_cache shared:SSL:10m;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;
        root /var/www/html;
        index index.html index.htm;
        location / {
            try_files \\\$uri \\\$uri/ =404;
# Proxy settings pointing to the Sphinx instance if on another port
#        proxy_pass http://localhost:8000;
#        proxy_http_version 1.1;
#        proxy_set_header Upgrade \\\$http_upgrade;
#        proxy_set_header Connection 'upgrade';
#        proxy_set_header Host \\\$host;
#        proxy_cache_bypass \\\$http_upgrade;
   }
}
EOT
exit
EOC

rm /var/www/html/index.nginx-debian.html
sudo systemctl stop nginx.service
sudo systemctl start nginx.service
sudo systemctl enable nginx.service

sudo apt-get install -y vsftpd
cp /etc/vsftpd.conf /etc/vsftpd.conf.orig
cat <<EOC | sudo su
cat <<EOT > /etc/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=NO
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES
ftpd_banner=Welcome to our FTP
listen=YES
pam_service_name
ascii_upload_enable=YES
ascii_download_enable=YES
use_localtime=YES
chroot_local_user=YES
EOT
exit
EOC

sudo useradd -m -p $ftppass1 -s /bin/bash $ftpUsername
echo $ftpUsername:$ftppass1 | sudo chpasswd

sudo usermod --home /var/www/html $ftpUsername
sudo chown nobody:nogroup /var/www
sudo chmod a-w /var/www
sudo chown $ftpUsername:$ftpUsername /var/www/html

sudo systemctl restart vsftpd

clear
echo "******************************************************************"
echo "Docs Server:" https://$eip
echo "Username:" $nginxUsername
echo "Password:" $passvar1
echo "******************************************************************"
echo "SSL cert:" /etc/pki/tls/certs/Sphinx.crt
echo "Sphinx Docs:" /var/www/html
echo "Nginx:" /etc/nginx/sites-available/default
echo "FTP:" /etc/vsftpd.conf
echo "******************************************************************"
echo "SFTP Server:" $eip
echo "Username:" $ftpUsername
echo "Password:" $ftppass1
echo "******************************************************************"