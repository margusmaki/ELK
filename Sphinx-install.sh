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
    exec sudo $0 $@ || echo "Sphinx installation must be run as root user"
    exit 1 # Fail Sudo
fi

#Ask some info
echo "Enter Sphinx Server IP or FQDN:"
read eip
echo "Create credentials for Sphinx web access:"
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
        server_name 10.104.32.25;
        return 301 https://\\\$server_name\\\$request_uri;
}
server {
        listen 443 default ssl;
        ssl_certificate /etc/pki/tls/certs/Sphinx.crt;
        ssl_certificate_key /etc/pki/tls/private/Sphinx.key;
        ssl_session_cache shared:SSL:10m;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;
        root /var/www/project;
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
sudo systemctl stop nginx.service
sudo systemctl start nginx.service
sudo systemctl enable nginx.service

clear
echo "******************************************************************"
echo "Login Docs Server:" https://$eip
echo "Username:" $nginxUsername
echo "Password:" $passvar1
echo "******************************************************************"
echo "SSL cert:" /etc/pki/tls/certs/Sphinx.crt
echo "Sphinx Docs:" /var/www/project
echo "Nginx:" /etc/nginx/sites-available/default
echo "******************************************************************"