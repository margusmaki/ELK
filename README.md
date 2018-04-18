# README #

NELK Installation Script (Elasticsearch, Logstash, Kibana & Nginx)

### What is this repository for? ###

* This script installs and configures every single component of the ELK Stack, Beats, Certificates, Nginx SSL Reverse Proxy and creates pre-configured Client side automated install file.
* Consists of 2 releases, Elasticsearch 5 and 6.
* ELK-install.sh (with elastic-6.x) & ELK-install-5.sh (with elastic-5.x)
* Tested on Ubuntu 16.04.04 LTS
* Version: 0.1

### How do I get set up? ###

* Pre-Req:
* Ubuntu 16.04 LTS default install 
* Static IP
* Hostname
* Hosts file

#### ELK Server install Github ####

* Github git:
* apt-get install -y git
* git clone https://github.com/margusmaki/ELK
* cp ELK/ELK-install.sh .
* chmod +x ELK-install.sh
* rm -rf ELK
* ./ELK-install.sh
*
* Github cURL
* curl -O https://raw.githubusercontent.com/margusmaki/ELK/master/ELK-install.sh
* chmod +x ELK-install.sh
* ./ELK-install.sh

#### ELK Server install Bitbucket ####

* Bitbucket git:
* apt-get install -y git
* git clone https://margusmaki@bitbucket.org/margusmaki/ELK.git
* cp ELK/ELK-install.sh .
* chmod +x ELK-install.sh
* rm -rf ELK
* ./ELK-install.sh
*
* Bitbucket cURL
* curl -O https://raw.githubusercontent.com/margusmaki/ELK/master/ELK-install.sh
* chmod +x ELK-install.sh
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
* Or: sed 's/\r//' filename.sh > otherfilename.sh
* Or commit with normal client (GitKraken or SourceTree)

### Who do I talk to? ###

* margus

### Credits ###
* Original Fork Credits to sniper7kills/ELK-install.sh 
* Credits for some coding tips to silentbreaksec/helk-installer.sh