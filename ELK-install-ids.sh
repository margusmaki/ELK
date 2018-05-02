#/bin/bash
#elastic-6.x
#Show primary IP & FQDN
clear
echo "******************************************************************"
echo "* Your IP address:	" $(ifconfig | awk '/inet addr/{print substr($2,6)}'| head -n 1)
echo "* Your FQDN:		" $(hostname -A)
echo "* Your System:		" $(cat /etc/issue.net)
echo "******************************************************************"

workingdir=$(pwd)
if [[ ! $EUID -eq 0 ]]; then
    exec sudo $0 $@ || echo "ELK Installation must be run as root user"
    exit 1 # Fail Sudo
fi

#Ask some info
echo "Enter ELK Server IP or FQDN:"
read eip
echo "Create credentials for ELK web access:"
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

#Pre-Req
sudo apt-get install -y curl debconf-utils

#Install Wazuh-Manager
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
sudo apt-get install -y wazuh-manager
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-6.x.list
apt-get update

#Install Wazuh-API
curl -sL https://deb.nodesource.com/setup_6.x | bash -
sudo apt-get install -y nodejs
sudo apt-get install -y wazuh-api

#Java Pre-Req
sudo apt-get install -y software-properties-common python-software-properties
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | sudo debconf-set-selections
sudo apt-get install -y oracle-java8-installer

#Add Repo Info
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install -y apt-transport-https
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
sudo apt-get update

#Trust self-signed cert by IP as CA
#insert after by name
sed -i "/ v3_ca /a subjectAltName = IP: $eip" /etc/ssl/openssl.cnf
#insert after by line number
# sed -i '226s/.*/subjectAltName = IP: '"$eip"'/' /etc/ssl/openssl.cnf
#Generate SSL Certificates
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private
cd /etc/pki/tls; sudo openssl req -subj '/CN='$eip'/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/ELK-Stack.key -out certs/ELK-Stack.crt

#ElasticSearch
sudo apt-get install -y elasticsearch
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/backup_elasticsearch.yml
#echo "network.host: 0.0.0.0" | sudo tee /etc/elasticsearch/elasticsearch.yml
sed -i 's/#network.host.*/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
sudo apt-get update
curl https://raw.githubusercontent.com/wazuh/wazuh/3.2/extensions/elasticsearch/wazuh-elastic6-template-alerts.json | curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-

#Logstash
sudo apt-get install -y logstash
curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/3.2/extensions/logstash/01-wazuh-local.conf

usermod -a -G ossec logstash
echo logstash:$passvar1 | chpasswd

sudo systemctl daemon-reload
sudo systemctl enable logstash.service
sudo systemctl restart logstash.service

#Kibana
sudo apt-get install -y kibana
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.2.1_6.2.4.zip
cp /etc/kibana/kibana.yml /etc/kibana/backup_kibana.yml
cat <<EOC | sudo su
cat <<EOT > /etc/kibana/kibana.yml
server.host: "0.0.0.0"
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable kibana.service
sudo systemctl start kibana.service

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
        ssl_certificate /etc/pki/tls/certs/ELK-Stack.crt;
        ssl_certificate_key /etc/pki/tls/private/ELK-Stack.key;
        ssl_session_cache shared:SSL:10m;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;
        location / {
# Proxy settings pointing to the Kibana instance
	    proxy_pass http://localhost:5601/;
	    proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \\\$host;
        proxy_cache_bypass \\\$http_upgrade;
   }
}
EOT
exit
EOC
sudo systemctl restart nginx

clear
echo "******************************************************************"
echo "Login ELK Server:" https://$eip
echo "Username:" $nginxUsername
echo "Password:" $passvar1
echo "******************************************************************"
echo "SSL cert:" /etc/pki/tls/certs/ELK-Stack.crt
echo "******************************************************************"
echo "SSL cert:" /etc/pki/tls/certs/ELK-Stack.crt
echo "Elasticsearch:" /etc/elasticsearch/elasticsearch.yml
echo "Kibana:" /etc/kibana/kibana.yml
echo "Logstash:" /etc/logstash/logstash.conf
echo "Logstash Wazuh:" /etc/logstash/conf.d/01-wazuh.conf
echo "Nginx:" /etc/nginx/sites-available/default
echo "******************************************************************"