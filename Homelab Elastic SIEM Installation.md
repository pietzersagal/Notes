# Document Intent
This is to serve is a guide for setting up an Elastic SIEM for homelab on your own hardware. This guide is designed for your SIEM to not be public facing, but to still expect others on your network. We will be following and referencing the official elastic documentation throughout this guide, but this guide will be more step by step than elastic's documentation with the addition of recommended configurations throughout. Your resources will likely differ from mine, so feel free to also follow along with Elastic's documentation for edge cases. 

**Note:** My configuration takes place on one virtual machine with 8 GB of Ram and a 1000 GB hard drive (though you can likely get away with a lot less). This installation takes place on an Ubuntu 24.04 Server with a statically assigned IP address.

This guide will be broken up into the following parts:
1. Elastic Search Installation
	1. Elastic Search's Role
	2. Installation
	3. Verification
2. Kibana Installation
	1. Kibana's Role
	2. Installation
	3. Enable HTTPS
	4. Fleet setup
3. Connecting an Agent
	1. Why Agent over Beats
	2. What are Integrations
	3. Connecting a Linux Agent
	4. Connecting a Windows Agent
4. Configuring alerts
	1. What to Create Alerts On
	2. How to Create an Alert
5. Hardening
	1. Configure Firewall
	2. Set important file permissions

# Elastic Search Installation
## Elastic Search's Role
While I think it is important to know the role of each part of your SIEM, if you want to move forward with the installation then jump to the Installation step. 

Elastic search is described as "an open source, distributed search and analytics engine built for speed, scale, and AI applications". Which to put more simply, it is a platform to store and search logs with some programmatic features baked in. Elastic offers many different versions of the software running on different code languages, however the most common and the one we will be using is Java with a bundled in JDK. By default TLS encryption is enabled on the basic install of ES. To send logs to ES port 9200 will be opened on the host. To actually view these logs we will be using Elastic's Kibana, which we will go into in its respective section.

## Installation
Luckily the installation of Elastic Search is pretty straight forward to the official installation guide provided by elastic which can be found [here](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/installing-elasticsearch). We will primarily following this word for word.

1. Import Elasticsearch PGP key:
   `$ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg`
2. Install apt transport https
   `$ sudo apt-get install apt-transport-https`
3. Save repository definition
   `$ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list`
4. Next, update and install
   `$ sudo apt-get update && sudo apt-get install elasticsearch`
5. Observe the output of installing elastic search: ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Elastic_Installation_Output.png]]
   Here we can see in the output a password is generated for our build in user, "NH7AQphIpvhxcEL-ZE6n". On your installation please keep note of this password. If you have lost this password then you will have to generate a new one with `/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic` or as your output directs you to. 
6. Now obtain your IP address then open `/etc/elasticsearch/elasticsearch.yml` in your text editor of choice. Uncomment the line
   `#network.host: 192.168.0.1`
   And change this to
   `network.host: <YOUR-IP>`
   This will enable elastic search to listen on all interfaces. Also uncomment the line 
   `#transport.host: <YOUR-IP>`. 
7. Next enable systemd journal logging for the elasticsearch service by navigating to your elasticsearch.service file. In my case it is located at `/usr/lib/systemd/system/elasticsearch.service`
   Find the line
   `ExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid --quiet`
   and remove the `--quiet` part from it
   `ExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid`
8. Finally, daemon-reload, enable and start the service
   `$ sudo systemctl daemon-reload`
   `$ sudo systemctl enable elasticsearch.service`
   `$ sudo systemctl start elasticsearch.service`
## Verification
Luckily verification that the service is running is quite easy.
`$ systemctl status elasticsearch.service`
This command should display that the service is active and enabled as shown here: ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Elastic_Running.png]]
Afterwards you can verify that the service is able to receive information by querying it. For the following command please replace the elastic password with the one you had stored in step 5.
`$ sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:<ELASTIC-PASSWORD> https://localhost:9200`
You should receive a response like the following:![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Elastic_Verification.png]]

Congratulations, once reaching this step you have successfully installed elastic search

# Kibana
## Kibana's Role
Kibana will be the primary way you are able to interact with your SIEM. 

Kibana is a web server that you host in order to view logs, setup fleets, create dashboards, and about everything else that you might want to do with your SIEM. 

## Installation
1. Install the Kibana package: 
   `$ sudo apt-get install kibana`
2. Make the host externally accessible, modifying `/etc/kibana/kibana.yml` and changing the line
   `#server.host: "localhost"`
   to
   `server.host: <YOUR-IP>`
3. Now setup and start Kibana with systemd
   `$ sudo systemctl daemon-reload`
   `$ sudo systemctl enable kibana`
   `$ sudo systemctl start kibana`
4. Next enroll Kibana, obtain the verification code via the command:
   `$ systemctl status kibana`
   That will show an output like so: ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Verification.png]]
   At the bottom we will see text like `Go to http://172.16.0.13:5601/?code=892613 to get started.` Visit the URL provided in your web browser to enable your Kibana instance. Next you will see a page prompting you for an enrollment token:![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Enrollment.png]]
   Generate an enrollment token with the following command
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`
   Copy the output of that command and paste it into the Enrollment token window on your browser, then click "Configure Elastic". Please give Kibana a moment until you are able to see the following login page: ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Login.png]]

Now you can login with the username elastic and your password generated from the elastic installation earlier. If you have lost this password a new one can be generated with the command: 
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic`
   However there are some additional configurations that you should be doing. These are detailed in the next Section

## Enable HTTPS
You are using a password to sign in meaning that it shouldn't be seen in plain text across the network. 
1. First generate a certificate using elastic search
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-certutil csr --name kibana-server --out /etc/kibana/kibana-server.zip`
2. Next unzip the contents
   `$ sudo unzip /etc/kibana/kibana-server.zip -d /etc/kibana`
3. Move the contents to the main folder
   `$ sudo mv /etc/kibana/kibana-server/kibana-server.key /etc/kibana` 
   `$ sudo mv /etc/kibana/kibana-server/kibana-server.csr /etc/kibana`
4. Create the crt file with openssl
   `$ sudo openssl req -in /etc/kibana/kibana-server.csr -out /etc/kibana/kibana-server.pem`
   `$ sudo openssl x509 -req -in /etc/kibana/kibana-server.pem -signkey /etc/kibana/kibana-server.key -out /etc/kibana/kibana-server.crt`
5. Next edit the /etc/kibana/kibana.yml file. Change the lines
   ```
   #server.ssl.enabled: false
   #server.ssl.certificate: /path/to/your/server.crt
   #server.ssl.key: /path/to/your/server.key
   ```
To these lines
```
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/kibana-server.crt
server.ssl.key: /etc/kibana/kibana-server.key
```
6. Finally restart Kibana
   `$ sudo systemctl restart kibana`
You should now observe that you can only access Kibana via https now and that you will get a warning about your certificate when visiting the webpage. To fix this you would need to setup your own certificate authority which unfortunately is outside the scope of this guide and to be frank not needed for a small scale home lab.
## Fleet setup
A fleet is used to centrally mange your Kibana integrations. Integrations allow you to create agents to monitor specific logs and be quickly updated via your fleet. But first you need to setup your fleet via Kibana.

1. First we need to generate some encryption keys for Kibana saved objects, this will allow us to setup Fleets. Run the following command to generate your encryption keys. 
   `$ sudo /usr/share/kibana/bin/kibana-encryption-keys generate`
2. You will get an output similar to the following. Note down and copy the values at the bottom. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Generate_Keys.png]]
3. Using a file editor of your choice append the following into the bottom of /etc/kibana.yml, substituting in your keys.
```
# This section was added after running "/usr/share/kibana/bin/kibana-encryption-keys generate"

xpack.encryptedSavedObjects.encryptionKey: <YOUR-SAVEDOBJECTS-KEY>
xpack.reporting.encryptionKey: <YOUR-REPORTING-KEY>
xpack.security.encryptionKey: <YOUR-SECURITY-KEY>
```
4. Now restart Kibana to apply the configurations.
   `$ sudo systemctl restart kibana`
5. Sign into Kibana, and when prompted to add integrations select "Explore on my own".![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet1.png]]
6. Next click the three bars in the top left and in the drop down go to Management > Fleet.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet2.png]]
7. Now click the button in the middle of the screen for Add Fleet Server. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet3.png]]
8. Now Follow the quick start guide, for our purpose we'll be using the Name "Fleet", the URL https://YOUR-IP:8220 and checking the switch to make this fleet server the default one. You may want to modify those as you see fit. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet4.png]]
9. Step 2 of the quick start will provide you with the commands you need to paste into your SIEM host to setup the Fleet on that server. Select your OS and architecture then paste those in to your terminal.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet5.png]]
10. After the successful running of those commands you will see the following output in the terminal: `Elastic Agent has been successfully installed.`
11. Jump back over to your browser and select the button "Continue enrolling Elastic Agent" in the third step.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet6.png]]
12. After this you will be prompted to create an agent since this will dependent on what sort of logs you want to collect click the 'X' for now. Then you should see a page like the following showing that you have your Fleet successfully setup! ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet7.png]]

# Connecting an Agent
## Why Agent over Beats
There are two ways to send logs back to elastic search from a host machine. The first way that was integrated was via a beat. Beats were designed to be lightweight data shippers for a specific purpose such as just getting a heartbeat from the system or collecting specific files for their logs. Because of beats having a specific purpose it is not uncommon to install multiple beats on one host in order to cover all aspects. However, beats can be hard to manage because of there potentially being multiple beats per host to change. Later on elastic introduced agents which provide the same functionality as many beats in one binary and are more easily manageable. Agents are not an exact one to one with beats, but are far easier to use, deploy, and manage. In addition, elastic is pushing users to swap over to agents wherever applicable. Therefore, we will only be going over the installation of Agents in this guide. If you are still curious, you can take a look at the official elastic documentation [here](https://www.elastic.co/docs/reference/fleet/beats-agent-comparison)

## What are Integrations
You may remember that we were prompted to setup an integration when we first logged into Kibana. This is because integrations actually manage the agents. So in reality Fleets manage the integrations which in turn manage the agents. Different integrations can control things such as the OS/architecture the agents is configured for or what sort of data is being collected. There are many different applications to go over with agents, but to keep it simple we will go over Linux and Windows.

## Connecting a Linux Agent
As a bit of a preface there are many different configurations of Linux, you may have to change some things that I do in order to fit your specific linux installation. To add some additional context the host I am connecting is an Ubuntu server with x86_64 architecture. Additionally, **any commands executed from the terminal are on the host we want to send logs from.** The commands are **NOT** executed on the host of the SIEM. There shouldn't be anything wrong with deploying agents on the SIEM host (You actually have already when you setup the fleet), but this guide aims to connect external computers to your SIEM.

1. From the homepage click on the three bars in the top left then click on Management -> Integrations.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent1.png]]
2. In the search bar type "system", then click on the System integration. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent2.png]]
3. In the top right click "Add System".![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent3.png]]
4. You will then be brought to a page to configure your integration. To keep things simple we will keep things on their default, but feel free to change the defaults to meet your needs. For example for a Mac you might need to add additional rows to the "Collect logs from System Instances".![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent4.png]]
5. In step 2, select "New hosts" and feel free to change the "New agent policy name". When done click "Save and continue" in the bottom right.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent5.png]]
6. You'll get a popup stating the system integration was added, now click "Add Elastic Agent to your hosts"![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent6.png]]
7. You'll be brought back to your system integration overview, click on the "Add agent" button for your newly created integration policy. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent7.png]]
8. You'll have a side bar open up for adding an agent. For step one you can use the default enrollment token. For step two select the correct OS and architecture from the tabs and then copy the commands provided to you. Don't paste them just yet, since we are operating within a home lab we will get some errors about our certificates since they are not registered with a proper CA. We will have to modify them.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent8.png]]
9. You can safely enter in the first three lines that curl a tar file, uncompress it, then change into the directory. 
10. However in the final line we need to append `--insecure` since we have not setup our certificates with a CA. So your final command entered should look something like the following:
    `$sudo ./elastic-agent install --url=https://172.16.0.13:8220 --enrollment-token=WW91J3JlIGEgbm9zZXkgYmFzdGFyZCBhcmVuJ3QgeWE= --insecure`
11. After that you will get confirmation that your agent has been enrolled and you will be prompted to click "View assets". Instead click the three bars in the top left and click Analytics > Discover. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent9.png]]
12. You can now observe that you are receiving logs from the host via your agent. Congratulations! ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Linux_Agent10.png]]
## Connecting a Windows Agent

This will be very similar to connecting a Linux agent. As a matter of fact we are changing very little. However, I wanted to make this a different section to show you the slight differences. As before the commands entered here are done on a windows host and **NOT** our SIEM host.

1. From the home page, click on the three bars in the top left and select Management -> Integrations.![[Windows1.png]]
2. On the integrations page, type in "Windows" into the search bar and select the Windows Integration.![[Windows2.png]]
3. On the windows integration page, click Add Windows![[Windows3.png]]
4. Give your integration a meaningful name and description. Then go into "Collect events from the following Windows event log channels:", then modify this to as you see fit. The more boxes you check the more logs your SIEM will have to process. However it is highly recommended that you install Sysmon on your host and check the "Sysmon Operational" box. Personally I also like to check the "Preserve original event" for the Sysmon logs as well. You can find the Sysmon download [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and I recommend to start out with one of the community Sysmon config files such as the one from SwiftOnSecurity found [here](https://github.com/SwiftOnSecurity/sysmon-config?tab=readme-ov-file).![[Windows4.png]]![[Windows5.png]]
5. Next give you new agent policy a name and click "Save and continue" in the bottom right.![[Windows6.png]]
6. Next on the window that has popped up click "Add Elastic Agent to your hosts"![[Windows7.png]]
7. You'll now be back on the Windows integration page, click on "Add agent" for your newly created integration.![[Windows8.png]]
8. Skip over step one and in step two select your OS and architecture/preferred way of installation. For me is is "Windows MSI".![[Windows9.png]]
9. Now, open PowerShell **as administrator**. And paste the text provided to you by elastic in your PowerShell terminal. After you run the code, you'll see something similar to the following in the terminal awaiting you to press enter
   `> .\elastic-agent-9.2.1-windows-x86_64.msi --% INSTALLARGS="--url=https://172.16.0.13:8220 --enrollment-token=RG9uJ3QgdXNlIG15IGVucm9sbG1lbnQga2V5LCBnbyBnZXQgeW91ciBvd24hID46KA=="`
   Since we are in charge of our own certificates we will have to append `--insecure` to the INSTALLARGS variable. So you should change your command to look something like the following: `> .\elastic-agent-9.2.1-windows-x86_64.msi --% INSTALLARGS="--url=https://172.16.0.13:8220 --enrollment-token=RG9uJ3QgdXNlIG15IGVucm9sbG1lbnQga2V5LCBnbyBnZXQgeW91ciBvd24hID46KA== --insecure"`
10. Next just follow the provided installation wizard. ![[Windows10.png]]
11. After this you'll get confirmation back in your browser window that your windows host is now sending logs to elastic.![[Windows11.png]]
12. Now click on the three bars in the top left and go to Analytics > Discover.![[Windows12.png]]
13. You'll now be able to confirm that your windows host is sending logs to your SIEM. Congratulations. ![[Windows13.png]]

# Configuring alerts
## What to Create Alerts On
The primary purpose of your SIEM should be to keep an eye on all of your machines. However, it is not reasonable to search for IOC on **every** host that you connect. So you should create alerts to notify you when something should be investigated. This can be a hard thing to do and there are many ways to go about it. One thing is true regardless, your alerting rules will continue to grow and change over time. In my personal opinion, the best place to start is with the [MITRE ATT&CK framework](https://attack.mitre.org/). This is a framework that lists a knowledge base of known adversary tactics and techniques. For your specific setup not all tactics will be applicable to you, such as T1201 (Password Policy Discovery). However, it is a good place to start
## How to Create an Alert
The main point of an alert is to cause further action when a certain log or pattern of logs appear. In a traditional SOC this is where a playbook would run to automate the remediation process and or an analyst would jump in to investigate. For our purposes we will create an alert that appears on the alert page and prompts you to investigate. For our demonstrative purposes, we will create an alert for a failed linux authentication. 

1. Click the three bars in the top left and go to Security > Alerts. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert1.png]]
2. On the Alerts page, click on the "Manage Rules" button in the top right.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert2.png]]
3. On the Rule page click on the "Create rule" button in the top left. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert3.png]]
4. **NOTE:** *At this point depending on what you want to alert on your actions may differ.* In the "Select rule type" window, type "Elasticsearch query", then click the Elasticsearch box.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert4.png]]
5. You'll then be brought to a query rule page and prompted to select a query type. This is up to your preference, in my situation I find "ES|QL" to be my preferred query language due to its powerful capabilities. Then enter in the query you would want to alert for. In my instance I'm using a very basic failed authentication query. Additionally I've selected my time field of choice to be @timestamp
   ```
   FROM logs-*
   | WHERE event.category : "authentication" AND event.outcome : "failure"
   ```
   ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert5.png]]
6. Next, I've configured this query to run once every minute and alert to everyone for every instance found. **NOTE:** Sometimes alerting behavior can generate multiple lines. You can avoid alert fatigue be improving the schedule and the query itself. 
7. We'll skip adding an action for this example and jump on to the third and final step creating rule details. I have filled mine out as seen below, but these are free for you to customize as you see fit. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert7.png]]
8. Next click on "Create rule" then "Save rule" when you are asked if you want no actions with your alert.![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert8.png]]
9. Finally we'll be brought to the rule's page. To verify if the alert is working you can either stay on the newly created rules page and observe the alerts tab at the bottom or navigate over to the alerts page via the drop down on the left and observe from there. Next jump onto a host with an agent setup and fail an authentication. For example
   `$ su root`
   You should see the alert pop up which is verifying that the SIEM is on the lookout for you. ![[https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert9.png]]
10. Now you can click and investigate the alert and take whatever action you deem necessary. NOTE: For our instance, once you click on the alert details the status will switch to resolved. You may not want this for your specific installation.

Congratulations, you now have a fully working SIEM with Elastic search! Before you go about doing anything else, below you'll find some basic hardening that you can do specific to elastic. If you are interested in more alerts I'll later be posting all of my alert queries, when done this will be updated with a link.

# Hardening
Here we'll be going over some admittedly basic hardening steps to do for your SIEM.

## Firewall
Solely for accessing the SIEM you only need the following ports open:

| Port Number | Service        |
| ----------- | -------------- |
| TCP/9200    | Elastic Search |
| TCP/5601    | Kibana         |
| TCP/8220    | Fleet          |
You can drop all other traffic. However, if you access your server with ssh or have any other services that are running on the machine, make sure to add those to your firewall before dropping all other traffic and enabling the firewall.

## Kibana
Due to some reminiscence of us setting up our own certificate, we should make sure that all the files in `/etc/kibana` are only accessible to root:kibana. Run `ls -la /etc/kibana` and ensure that all files are owned by root with the kibana group and that there are no read permissions for you certificate files, especially your key.
