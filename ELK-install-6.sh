#/bin/bash
#elastic-6.x
#Show primary IP & FQDN
clear
echo "******************************************************************"
echo "* Your IP address:	" $(ifconfig | awk '/inet addr/{print substr($2,6)}'| head -n 1)
echo "* Your FQDN:		" $(hostname -A)
echo "* Your System:		" $(cat /etc/issue.net)
echo "******************************************************************"

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
sed -i 's/#network.host.*/network.host: 0.0.0.0/g' /etc/elasticsearch/elasticsearch.yml
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
sudo apt-get update

#Kibana
sudo apt-get install -y kibana
cp /etc/kibana/kibana.yml /etc/kibana/backup_kibana.yml
cat <<EOC | sudo su
cat <<EOT > /etc/kibana/kibana.yml
server.host: "localhost"
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

#Logstash
sudo apt-get install -y logstash
cat <<EOC | sudo su
cat <<EOT > /etc/logstash/conf.d/02-beats-input.conf
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/ELK-Stack.crt"
    ssl_key => "/etc/pki/tls/private/ELK-Stack.key"
  }
}
EOT
exit
EOC
cat <<EOC | sudo su
cat <<EOT > /etc/logstash/conf.d/10-syslog-filter.conf
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOT
exit
EOC
cat <<EOC | sudo su
cat <<EOT > /etc/logstash/conf.d/11-syslog-apache.conf
filter {
  if [source] =~ "apache" {
    if [source] =~ "access" {
      mutate { replace => { "type" => "apache_access" } }
      grok {
        match => { "message" => "%{COMBINEDAPACHELOG}" }
      }
    } else if [source] =~ "error" {
       mutate { replace => { type => "apache_error" } }
    } else {
       mutate { replace => { type => "apache_random"} }
    }
    date {
      match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }
}
EOT
exit
EOC
cat <<EOC | sudo su
cat <<EOT > /etc/logstash/conf.d/30-elasticsearch-output.conf
output {
  elasticsearch {
    hosts => "localhost:9200"
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOT
exit
EOC
sudo systemctl daemon-reload
sudo /usr/share/logstash/bin/logstash-plugin install logstash-input-beats
sudo systemctl enable logstash.service
sudo systemctl restart logstash.service

#Packetbeat
sudo apt-get install -y packetbeat
cat <<EOC | sudo su
cat <<EOT > /etc/packetbeat/packetbeat.yml
packetbeat.flows:
  timeout: 30s
  period: 10s
packetbeat.protocols.icmp:
  enabled: true
packetbeat.protocols.amqp:
  ports: [5672]
packetbeat.protocols.cassandra:
  ports: [9042]
packetbeat.protocols.dns:
  ports: [53]
  include_authorities: true
  include_additionals: true
packetbeat.protocols.http:
  ports: [80, 8080, 8000, 5000, 8002]
packetbeat.protocols.memcache:
  ports: [11211]
packetbeat.protocols.mysql:
  ports: [3306]
packetbeat.protocols.pgsql:
  ports: [5432]
packetbeat.protocols.redis:
  ports: [6379]
packetbeat.protocols.thrift:
  ports: [9090]
packetbeat.protocols.mongodb:
  ports: [27017]
packetbeat.protocols.nfs:
  ports: [2049]
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable packetbeat.service
sudo packetbeat export template > /etc/packetbeat/packetbeat.template.json
sudo packetbeat setup --dashboards

#Metricbeat
sudo apt-get install -y metricbeat
cat <<EOC | sudo su
cat <<EOT > /etc/metricbeat/metricbeat.yml
metricbeat.modules:
- module: system
  metricsets:
    - cpu
    - load
    - core
    - diskio
    - filesystem
    - fsstat
    - memory
    - network
    - process
  enabled: true
  period: 10s
  processes: ['.*']
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable metricbeat.service
sudo metricbeat export template > /etc/metricbeat/metricbeat.template.json
sudo metricbeat setup --dashboards

#Filebeat
sudo apt-get install -y filebeat
cat <<EOC | sudo su
cat <<EOT > /etc/filebeat/filebeat.yml
filebeat.prospectors:
- input_type: log
  paths:
    - /var/log/*/*.log
- document_type: syslog
  paths:
    - /var/log/syslog
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable filebeat.service
sudo filebeat export template > /etc/filebeat/filebeat.template.json
sudo filebeat setup --dashboards

sudo systemctl restart filebeat
sudo systemctl restart metricbeat
sudo systemctl restart packetbeat


###
# GENERATE CLIENT INSTALL SCRIPT
###
cat <<EOS > ~/ELK-client-install.sh
sudo apt-get update
sudo apt-get upgrade -y
#Add Repo Info
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
sudo apt-get update
#CERT
sudo mkdir -p /etc/pki/tls/certs
cat <<EOC | sudo su
cat <<EOT > /etc/pki/tls/certs/ELK-Stack.crt
$(sudo cat /etc/pki/tls/certs/ELK-Stack.crt)
EOT
exit
EOC
#Packetbeat
sudo apt-get install -y packetbeat
cp /etc/packetbeat/packetbeat.yml /etc/packetbeat/backup-packetbeat.yml
cat <<EOC | sudo su
cat <<EOT > /etc/packetbeat/packetbeat.yml
packetbeat.flows:
  timeout: 30s
  period: 10s
packetbeat.protocols.icmp:
  enabled: true
packetbeat.protocols.amqp:
  ports: [5672]
packetbeat.protocols.cassandra:
  ports: [9042]
packetbeat.protocols.dns:
  ports: [53]
  include_authorities: true
  include_additionals: true
packetbeat.protocols.http:
  ports: [80, 8080, 8000, 5000, 8002]
packetbeat.protocols.memcache:
  ports: [11211]
packetbeat.protocols.mysql:
  ports: [3306]
packetbeat.protocols.pgsql:
  ports: [5432]
packetbeat.protocols.redis:
  ports: [6379]
packetbeat.protocols.thrift:
  ports: [9090]
packetbeat.protocols.mongodb:
  ports: [27017]
packetbeat.protocols.nfs:
  ports: [2049]
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable packetbeat.service
#Metricbeat
sudo apt-get install -y metricbeat
cp /etc/metricbeat/metricbeat.yml /etc/metricbeat/backup-metricbeat.yml
cat <<EOC | sudo su
cat <<EOT > /etc/metricbeat/metricbeat.yml
metricbeat.modules:
- module: system
  metricsets:
    - cpu
    - load
    - core
    - diskio
    - filesystem
    - fsstat
    - memory
    - network
    - process
  enabled: true
  period: 10s
  processes: ['.*']
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable metricbeat.service
#FileBeat
sudo apt-get install -y filebeat
cp /etc/filebeat/filebeat.yml /etc/filebeat/backup-filebeat.yml
cat <<EOC | sudo su
cat <<EOT > /etc/filebeat/filebeat.yml
filebeat.prospectors:
- input_type: log
  paths:
    - /var/log/*/*.log
- document_type: syslog
  paths:
    - /var/log/syslog
output.logstash:
  hosts: ["$eip:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ELK-Stack.crt"]
EOT
exit
EOC
sudo systemctl daemon-reload
sudo systemctl enable filebeat.service
sudo systemctl restart filebeat
sudo systemctl restart metricbeat
sudo systemctl restart packetbeat
EOS
clear
echo "******************************************************************"
echo "Login ELK Server:" https://$eip
echo "Username:" $nginxUsername
echo "Password:" $passvar1
echo "******************************************************************"
echo "SSL cert:" /etc/pki/tls/certs/ELK-Stack.crt
echo "Elasticsearch: /etc/elasticsearch/elasticsearch.yml
echo "Kibana: /etc/kibana/kibana.yml
echo "Logstash:" /etc/logstash/logstash.conf
echo "Logstash:" /etc/logstash/conf.d/02-beats-input.conf
echo "Logstash:" /etc/logstash/conf.d/10-syslog-filter.conf
echo "Logstash:" /etc/logstash/conf.d/11-syslog-apache.conf
echo "Logstash:" /etc/logstash/conf.d/30-elasticsearch-output.conf
echo "Packetbeat:" /etc/packetbeat/packetbeat.yml
echo "Metricbeat:" /etc/metricbeat/metricbeat.yml
echo "Filebeat:" /etc/filebeat/filebeat.yml
echo "Nginx:" /etc/nginx/sites-available/default
echo "******************************************************************"
echo "ELK-client-install.sh"
echo "scp ELK-client-install.sh user@clientIP:/home/client"
echo "chmod +x ELK-client-install.sh"
echo "./ELK-client-install.sh"
echo "******************************************************************"