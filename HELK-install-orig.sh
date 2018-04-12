#!/bin/bash
# HELK Installation Script (Elasticsearch, Logstash, Kibana & Nginx)
# HELK build version: 0.9 (BETA Script)
# Author: Roberto Rodriguez @Cyb3rWard0g

# Description: This script installs every single component of the ELK Stack plus Nginx
# Blog: https://cyberwardog.blogspot.com/2017/02/setting-up-pentesting-i-mean-threat_98.html

# Fork version: 0.1
# Fork Author: Ryan Watson @gentlemanwatson
# Fork Project: HELK Setup


LOGFILE="/var/log/helk-install.log"

echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

echo "Starting HELK installation...."
echo "Enter credentials for accessing the web ELK console"

read -p 'Username: ' nginxUsername

while true; do
    read -p 'Password: ' passvar1
    echo
    read -p 'Verify Password: ' passvar2
    echo
    [ "$passvar1" == "$passvar2" ] && break
    echo "Passwords do not match..."
done

echo "[HELK INFO] Commenting out CDROM in /etc/apt/sources.list.."
sed -i '5s/^/#/' /etc/apt/sources.list >> $LOGFILE 2>&1

echo "[HELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
        exit
    fi

echo "[HELK INFO] Disabling IPV6.."

echo "  net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "  net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "  net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Unable to edit /etc/sysctl.conf (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Installing oracle-java8-installer"
sudo apt-get install -y software-properties-common python-software-properties debconf-utils >> $LOGFILE 2>&1
sudo add-apt-repository -y ppa:webupd8team/java >> $LOGFILE 2>&1
sudo apt-get update >> $LOGFILE 2>&1
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | sudo debconf-set-selections
sudo apt-get install -y oracle-java8-installer 2>&1

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install oracle-java8-installer (Error Code: $ERROR)."
    fi


# Elastic signs all of their packages with their own Elastic PGP signing key.
echo "[HELK INFO] Downloading and installing (writing to a file) the public signing key to the host.."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not write the public signing key to the host (Error Code: $ERROR)."
    fi

# Before installing elasticsearch, we have to set the elastic packages definitions to our source list.
# For this step, elastic recommends to have "apt-transport-https" installed already or install it before adding the elasticsearch apt repository source list definition to your /etc/apt/sources.list
echo "Installing apt-transport-https.."
apt-get install apt-transport-https >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install apt-transport-https (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Adding elastic packages source list definitions to your sources list.."
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not add elastic packages source list definitions to your source list (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Creating SSL Certificates.."
HOSTIPADDR=$(ifconfig | awk '/inet addr/{print substr($2,6)}'| head -n 1) >> $LOGFILE 2>&1
sed -i '226s/.*/subjectAltName = IP: '"$HOSTIPADDR"'/' /etc/ssl/openssl.cnf >> $LOGFILE 2>&1
mkdir -p /etc/pki/tls/certs >> $LOGFILE 2>&1
mkdir /etc/pki/tls/private >> $LOGFILE 2>&1
openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/ELK-Stack.key -out /etc/pki/tls/certs/ELK-Stack.crt

# *********** Installing Elasticsearch ***************
echo "[HELK INFO] Installing Elasticsearch.."
apt-get install elasticsearch >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install elasticsearch (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Creating a backup of Elasticsearch's original yml file.."
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/backup_elasticsearch.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of the elasticsearch.yml config (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] editing /etc/elasticsearch/elasticsearch.yml.."
sed -i 's/#network.host.*/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml >> $LOGFILE 2>&1

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not edit elasticsearch config (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Starting elasticsearch and setting elasticsearch to start automatically when the system boots.."
systemctl daemon-reload >> $LOGFILE 2>&1
systemctl enable elasticsearch.service >> $LOGFILE 2>&1
systemctl start elasticsearch.service >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start elasticsearch and set elasticsearch to start automatically when the system boots (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
    fi

# *********** Installing Kibana ***************
echo "[HELK INFO] Installing Kibana.."
apt-get install -y kibana >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install kibana (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Creating a backup of Kibana's original yml file.."
cp /etc/kibana/kibana.yml /etc/kibana/backup_kibana.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of Kibana's original yml file (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] editing /etc/kibana/kibana.yml.."
sed -i 's/#server.host:.*/server.host: localhost/g' /etc/kibana/kibana.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not edit kibana.yml file (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Starting kibana and setting kibana to start automatically when the system boots.."
systemctl daemon-reload >> $LOGFILE 2>&1
systemctl enable kibana.service >> $LOGFILE 2>&1
systemctl start kibana.service >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start kibana and set kibana to start automatically when the system boots (Error Code: $ERROR)."
    fi

# *********** Installing Nginx ***************
echo "[HELK INFO] Installing Nginx.."
apt-get install -y nginx apache2-utils >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install nginx (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Adding a user ' $nginxUsername '::' $passvar1 'htpasswd.users file to nginx.."
htpasswd -b -c /etc/nginx/htpasswd.users $nginxUsername $passvar1 >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not add user Hunter to htpasswd.users file (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Backing up Nginx's config file.."
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/backup_default >> $LOGFILE 2>&1
sudo truncate -s 0 /etc/nginx/sites-available/default >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of nginx config file (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Creating custom nginx config file to /etc/nginx/sites-available/default.."

HOSTIPADDR=$(ifconfig | awk '/inet addr/{print substr($2,6)}'| head -n 1)

newDefault="
    server {
        listen 80 default_server; # Listen on port 80
        server_name ""$HOSTIPADDR""; # Bind to the IP address of the server
        return         301 https://\$server_name\$request_uri; # Redirect to 443/SSL
   }
    server {
        listen 443 default ssl; # Listen on 443/SSL
        # SSL Certificate, Key and Settings
        ssl_certificate /etc/pki/tls/certs/ELK-Stack.crt ;
        ssl_certificate_key /etc/pki/tls/private/ELK-Stack.key;
        ssl_session_cache shared:SSL:10m;
        # Basic authentication using the account created with htpasswd
        auth_basic \"Restricted Access\";
        auth_basic_user_file /etc/nginx/htpasswd.users;
        location / {
     # Proxy settings pointing to the Kibana instance
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
        }
    }
"
echo "$newDefault" >> /etc/nginx/sites-available/default

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create custom nginx file (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] testing nginx configuration.."
nginx -t >> $LOGFILE 2>&1

echo "[HELK INFO] Restarting nginx service.."
systemctl restart nginx >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not restart nginx (Error Code: $ERROR)."
    fi

echo "[HELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install update (Error Code: $ERROR)."
    fi

# *********** Installing Logstash ***************
echo "[HELK INFO] Installing Logstash.."
apt-get install logstash >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install logstash (Error Code: $ERROR)."
    fi
 
echo "[HELK INFO] Creating logstash's .conf files.."

BEATSINPUT="
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => \"/etc/pki/tls/certs/ELK-Stack.crt\"
    ssl_key => \"/etc/pki/tls/private/ELK-Stack.key\"
  }
}
"
touch /etc/logstash/conf.d/02-beats-input.conf
echo "$BEATSINPUT" >> /etc/logstash/conf.d/02-beats-input.conf

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create custom logstash file /etc/logstash/conf.d/02-beats-input.conf (Error Code: $ERROR)."
    fi


ELASTICSEARCHOUTPUT="
output {
  elasticsearch {
    hosts => [\"localhost:9200\"]
    sniffing => true
    manage_template => false
    index => \"%{[@metadata][beat]}-%{+YYYY.MM.dd}\"
    document_type => \"%{[@metadata][type]}\"
  }
}
"
touch /etc/logstash/conf.d/30-elasticsearch-output.conf
echo "$ELASTICSEARCHOUTPUT" >> /etc/logstash/conf.d/30-elasticsearch-output.conf

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create custom logstash file /etc/logstash/conf.d/30-elasticsearch-output.conf (Error Code: $ERROR)."
    fi
    
echo "[HELK INFO] Starting logstash and setting Logstash to start automatically when the system boots.."
systemctl start logstash >> $LOGFILE 2>&1
systemctl restart logstash >> $LOGFILE 2>&1
systemctl enable logstash >> $LOGFILE 2>&1

ERROR=$?
      if [ $ERROR -ne 0 ]; then
        echoerror "Could not start logstash and set it to start automatically when the system boots (Error Code: $ERROR)"
      fi
echo "**********************************************************************************************************"
echo "[HELK INFO] Your HELK has been installed"
echo "[HELK INFO] Browse to your Ubuntu Server and sign-in:"
echo "Username: " $nginxUsername
echo "Password: " $passvar1
echo "Additional Details:"
echo "SSL cert: /etc/pki/tls/certs/ELK-Stack.crt"
echo "**********************************************************************************************************"