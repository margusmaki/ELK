# README #

NELK Installation Script (Elasticsearch, Logstash, Kibana & Nginx)

### What is this repository for? ###

* This script installs and configures every single component of the ELK Stack, Beats, Certificates, Nginx SSL Reverse Proxy and creates pre-configured Client side automated install file.
* Tested on Ubuntu 16.04.04 LTS
* Version: 0.1

### How do I get set up? ###

* Pre-Req:
* Ubuntu 16.04 LTS default install 
* Static IP
* Hostname
* Hosts file

#### ELK Server install ####

* Github:
* apt-get install -y git
* git clone https://gist.github.com/margusmaki/c16f9dcaade7a12d7cf6adfc85a7f017
* cp c16f9dcaade7a12d7cf6adfc85a7f017/ELK-install.sh .
* chmod +x ELK-install.sh
* rm -rf c16f9dcaade7a12d7cf6adfc85a7f017
* ./ELK-install.sh

#### ELK Client install ####

* cd ~
* scp ELK-client-install.sh user@clientIP:/home/whatever
* ssh clientIP
* cd /home/whatever
* chmod +x ELK-client-install.sh
* ./ELK-client-install.sh

##### Tips'n'Tricks #####

* Editing or copy-paste etc in Windows can add some aliens to your code
* To check code: cat -v -e filename.sh
* To remove hidden windows characters from files: dos2unix filename.sh
* or
* sed 's/\r//' filename.sh > otherfilename.sh

### Who do I talk to? ###

* margus