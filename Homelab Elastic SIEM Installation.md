# Document Intent
This is to serve is a guide for setting up an Elastic SIEM for homelab on your own hardware. This guide is designed for your SIEM to not be public facing, but to still expect others on your network. We will be following and referencing the official elastic documentation throughout this guide, but this guide will be more step by step than elastic's documentation with the addition of recommended configurations throughout. Your resources will likely differ from mine, so feel free to also follow along with Elastic's documentation for edge cases. 

**Note:** My configuration takes place on one virtual machine with 12 GB of Ram and a 1000 GB hard drive (though you can likely get away with a lot less). This installation takes place on an Ubuntu 24.04 Server with a statically assigned IP address.

This guide will be broken up into the following parts:
1. [Elastic Search Installation](#elastic-search-installation)
	1. [Elastic Search's Role](#elastic-searchs-role)
	2. [Elastic Search Installation Steps](#elastic-search-installation-steps)
	3. [Verification](#verification)
2. [Kibana Installation](#kibana-installation)
	1. [Kibana's Role](#kibanas-role)
	2. [Kibana Installation Steps](#kibana-installation-steps)
	3. [Enable HTTPS](#enable-https)
	4. [Fleet Setup](#fleet-setup)
3. [Connecting an Agent](#connecting-an-agent)
	1. [Why Agent Over Beats](#why-agent-over-beats)
	2. [What are Integrations](#what-are-integrations)
	3. [Adding Agents](#adding-agents)
	   1. [Linux](#linux)
	   2. [Windows](#windows)
4. [Configuring Alerts](#configuring-alerts)
	1. [What to Create Alerts On](#configuring-alerts)
	2. [How to Create an Alert](#how-to-create-an-alert)
5. [Hardening](#hardening)
	1. [Configuring the Firewall](#configuring-the-firewall)
	2. [Kibana Hardening](#kibana-hardening)

# Elastic Search Installation
## Elastic Search's Role
While I think it is important to know the role of each part of your SIEM, if you want to move forward with the installation then jump to the Installation step. 

Elastic search is described as "an open source, distributed search and analytics engine built for speed, scale, and AI applications". Which to put more simply, it is a platform to store and search logs with some programmatic features baked in. Elastic offers many different versions of the software running on different code languages, however the most common and the one we will be using is Java with a bundled in JDK. By default TLS encryption is enabled on the basic install of ES. To send logs to ES port 9200 will be opened on the host, however you can find more about firewall configurations in the [Configuring the Firewall](#configuring-the-firewall) portion of this guide. To actually view these logs we will be using Elastic's Kibana, which we will go into in its respective section.

## Elastic Search Installation Steps
Luckily the installation of Elastic Search is pretty straight forward to the official installation guide provided by elastic which can be found [here](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/installing-elasticsearch). We will primarily following this word for word.

1. Import the Elasticsearch PGP key:
   
   `$ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg`
2. Install apt transport https
   
   `$ sudo apt-get install apt-transport-https`
3. Save the repository definition
   
   `$ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list`
4. Update and install
   
   `$ sudo apt-get update && sudo apt-get install elasticsearch`
5. Observe the output of installing elastic search: ![Elastic_Installation_Output.png](/Images/Elastic_SIEM/Elastic_Installation_Output.png)
   Here we can see in the output a password is generated for our build in user, `NH7AQphIpvhxcEL-ZE6n`. On your installation please keep note of this password. If you have lost this password then you will have to generate a new one with 
   
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic` or as your output directs you to. 
6. Now obtain your IP address then open `/etc/elasticsearch/elasticsearch.yml` in your text editor of choice. Uncomment the line
   
   `#network.host: 192.168.0.1`
   And change this to:
   
   `network.host: <YOUR-IP>`
   This will enable elastic search to listen on all interfaces. In addition add the following line below your newly created one:
   
   `#transport.host: <YOUR-IP>`. 
7. Next enable systemd journal logging for the elasticsearch service by navigating to your elasticsearch.service file. In my case it is located at `/usr/lib/systemd/system/elasticsearch.service`
   Find the line
   
   `ExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid --quiet`

   and remove the `--quiet` part from it

   `ExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid`
9. Finally, daemon-reload, enable and start the service
   
   ```
   $ sudo systemctl daemon-reload
   $ sudo systemctl enable elasticsearch.service
   $ sudo systemctl start elasticsearch.service
   ```
## Verification
Luckily verification that the service is running is quite easy.

`$ systemctl status elasticsearch.service`

This command should display that the service is active and enabled as shown here: ![Elastic_Running](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Elastic_Running)
Afterwards you can verify that the service is able to receive information by querying it. For the following command please replace the elastic password with the one you had stored in step 5 of [Elastic Search Installation Steps](#elastic-search-installation-steps).

`$ sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:<ELASTIC-PASSWORD> https://localhost:9200`

You should receive a response like the following:![Elastic_Verification](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Elastic_Verification)

Congratulations, once you have successfully installed elastic search!

# Kibana Installation
## Kibana's Role
Kibana will be the primary way you are able to interact with your SIEM. 

Kibana is a web server that you host in order to view logs, setup fleets, create dashboards, and about everything else that you might want to do with your SIEM. 

## Kibana Installation Steps
1. Install the Kibana package: 
   
   `$ sudo apt-get install kibana`
2. Make the host externally accessible, modifying `/etc/kibana/kibana.yml` and changing the line

   `#server.host: "localhost"` to `server.host: <YOUR-IP>`
4. Now setup and start Kibana with systemd

   ```
   $ sudo systemctl daemon-reload
   $ sudo systemctl enable kibana
   $ sudo systemctl start kibana
   ```
6. Next enroll Kibana, obtain the verification code via the command:

   `$ systemctl status kibana`

   That will show an output like so: ![Kibana_Verification](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Verification)
   At the bottom we will see text like the following:

   `Go to http://172.16.0.13:5601/?code=892613 to get started.`

   Visit the URL provided in your web browser to enable your Kibana instance. Next, you will see a page prompting you for an enrollment token:

   ![Kibana_Enrollment](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Enrollment)

   Generate an enrollment token with the following command

   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`

   Copy the output of that command and paste it into the Enrollment token window on your browser, then click "Configure Elastic". Please give Kibana a moment until you are able to see the following login page: ![Kibana_Login](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Login.png)

Now you can login with the username elastic and your password generated from the elastic installation earlier. If you have lost this password a new one can be generated with the command: 
   
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic`
   
   However there are some additional configurations that you should be doing. These are detailed in the following sections.

## Enable HTTPS
You are using a password to sign in meaning that it shouldn't be seen in plain text across the network. We'll generate a certificate and implement it to setup HTTPS so that we have no more plaintext traffic used for our password.
1. First generate a certificate using elastic search
   
   `$ sudo /usr/share/elasticsearch/bin/elasticsearch-certutil csr --name kibana-server --out /etc/kibana/kibana-server.zip`
   
2. Next unzip the contents
   
   `$ sudo unzip /etc/kibana/kibana-server.zip -d /etc/kibana`
   
3. Move the contents to the main folder
   ```
   $ sudo mv /etc/kibana/kibana-server/kibana-server.key /etc/kibana 
   $ sudo mv /etc/kibana/kibana-server/kibana-server.csr /etc/kibana
   ```
   
4. Create the crt file with openssl
   ```
   $ sudo openssl req -in /etc/kibana/kibana-server.csr -out /etc/kibana/kibana-server.pem
   $ sudo openssl x509 -req -in /etc/kibana/kibana-server.pem -signkey /etc/kibana/kibana-server.key -out /etc/kibana/kibana-server.crt
   ```
5. Next edit the `/etc/kibana/kibana.yml` file and change the lines
   ```
   #server.ssl.enabled: false
   #server.ssl.certificate: /path/to/your/server.crt
   #server.ssl.key: /path/to/your/server.key
   ```
   To these lines.
   ```
   server.ssl.enabled: true
   server.ssl.certificate: /etc/kibana/kibana-server.crt
   server.ssl.key: /etc/kibana/kibana-server.key
   ```
6. Finally restart Kibana

   `$ sudo systemctl restart kibana`
   
You should now observe that you can only access Kibana via https now and that you will get a warning about your certificate when visiting the webpage for the first time. To fix this you would need to setup your own certificate authority which unfortunately is outside the scope of this guide and to be frank not needed for a small scale home lab.
## Fleet Setup
A fleet is used to centrally mange your Kibana integrations. Integrations allow you to create agents to monitor specific logs on hosts. However, you first need to setup your fleet via Kibana.

1. First we need to generate some encryption keys for Kibana saved objects, this will allow us to setup Fleets. Run the following command to generate your encryption keys. 
   
   `$ sudo /usr/share/kibana/bin/kibana-encryption-keys generate`
   
2. You will get an output similar to the following. Note down and copy the values at the bottom. ![Kibana_Generate_Keys.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Kibana_Generate_Keys.png)
3. Using a file editor of your choice append the following into the bottom of `/etc/kibana.yml`, substituting in your keys.
```
# This section was added after running "/usr/share/kibana/bin/kibana-encryption-keys generate"

xpack.encryptedSavedObjects.encryptionKey: <YOUR-SAVEDOBJECTS-KEY>
xpack.reporting.encryptionKey: <YOUR-REPORTING-KEY>
xpack.security.encryptionKey: <YOUR-SECURITY-KEY>
```
4. Now restart Kibana to apply the configurations.

   `$ sudo systemctl restart kibana`
   
6. Sign into Kibana, and when prompted to add integrations select "Explore on my own".![Fleet1.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet1.png)
7. Next click the three bars in the top left and in the drop down go to Management > Fleet.![Fleet2.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet2.png)
8. Now click the button in the middle of the screen for Add Fleet Server. ![Fleet3.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet3.png)
9. Now Follow the quick start guide, for our purpose we'll be using the Name "Fleet", the URL https://YOUR-IP:8220 (using your SIEM's IP address) and checking the switch to make this fleet server the default one. You may want to modify these as you see fit. ![Fleet4.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet4.png)
10. Step 2 of the quick start will provide you with the commands you need to paste into your SIEM host to setup the Fleet on that server. Select your OS and architecture then paste those in to your terminal.![Fleet5.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet5.png)
11. After the successful running of those commands you will see the following output in the terminal: `Elastic Agent has been successfully installed.`
12. Jump back over to your browser and select the button "Continue enrolling Elastic Agent" in the third step.![Fleet6.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet6.png)
13. After this you will be prompted to create an agent, click the 'X' for now. Then you should see a page like the following showing that you have your Fleet successfully setup! ![Fleet7.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Fleet7.png)

# Connecting an Agent
## Why Agent Over Beats
There are two ways to send logs back to elastic search from a host machine. The first way that was integrated was via a beat. Beats were designed to be lightweight data shippers for a specific purpose, such as just getting a heartbeat from the system or collecting specific log files. Because of the nature of beats it is not uncommon to install multiple beats on one host in order to collect all wanted information. However, beats can be hard to manage due to there being no easy way to update them and potentially dealing with multiple beats on one host. Later on elastic introduced agents which provide the same functionality as many beats in one binary and are more easily manageable. Agents are not an exact one to one with beats, but are far easier to use, deploy, and manage. In addition, elastic is pushing users to swap over to agents wherever applicable. Therefore, we will only be going over the installation of Agents in this guide. If you are still curious about the differences, you can take a look at the official elastic documentation [here](https://www.elastic.co/docs/reference/fleet/beats-agent-comparison)

## What are Integrations
You may remember that we were prompted to setup an integration when we first logged into Kibana. To understand what an integration is we first need to know about Policies. Policies are used to create agents that collecting system logs or information under specific rules. As one host cannot have multiple agents sometimes the use of differently policies for different use cases is needed. For each policy you can setup many different integrations, which are the things that dictate what information the agents should be collecting. If an agent is created by a policy with one or more incompatible integrations (ex. Linux host has an agent with windows integrations) then the incompatible integration(s) will be ignored and only applicable information will be collected.

**TLDR**

*Policy*: Creates agents that collect information from the host under specific rules via one or more integrations.

*Agent*: A service on a host that sends logs back to Elasticsearch.

*Integration*: A set of rules an agent will follow.

## Creating a Security Policy
Here we'll show how to create a policy to be used for collecting logs that we can alert on as well as provide features for hosts that you would want in a typical SOC.

1. Go to Fleet page. From the main menu this can be accessed from the three bars in the top left and clicking on Management > Fleet.![SP1.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP1.png)
2. Next click on the "Agent policies" tab from the Fleet page.![SP2.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP2.png)
3. Next click on "Create agent policy".![SP3.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP3.png)
4. Choose a meaningful name like "Security Policy" and click on "Create agent policy".![SP4.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP4.png)
5. Now click on your newly created policy.![SP5.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP5.png)
6. Click on "Add integration" in the middle of the page.![SP6.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP6.png)
7. In the pop up menu search for and select "Elastic Defend", give you integration a meaningful name, optionally give your integration a description, and for your configuration settings you can leave the environment type as "Traditional Endpoints" and leave "Complete EDR" as the chosen setting. Then click "Add integration". ![SP7.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP7.png)  ![SP8.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP8.png)
8. You'll now be back at your policy page, click on your newly created Elastic Defend integration (You'll also see a system integration that exists to collect logs from linux hosts).![SP9.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP9.png)
9. In your integration settings, scroll down to "Protection level" and switch it to "Detect". You can experiment with this later, however when starting out you should leave this on detect as to not cause unintended issues. Then select "Save integration".![SP10.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP10.png)
10. You'll now be brought back to your policy page, if you don't plan on using any windows agents then you can skip these next steps. If you do, then click on "Add integration" again.![SP11.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP11.png)
11. Search for the integration "Windows" and give your integration a meaningful name and description. Then go into "Collect events from the following Windows event log channels:", then modify this to as you see fit. The more boxes you check the more logs your SIEM will have to process. However it is highly recommended that you install Sysmon on your host and check the "Sysmon Operational" box. Personally I also like to check the "Preserve original event" for the Sysmon logs as well. You can find the Sysmon download [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and I recommend to start out with one of the community Sysmon config files such as the one from SwiftOnSecurity found [here](https://github.com/SwiftOnSecurity/sysmon-config?tab=readme-ov-file). Once, done click on "Add integration". ![SP12.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP12.png)  ![SP13.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/SP13.png)
You'll now be back on the policy page with your policy setup. Now we can worry about adding agents from this policy to our hosts.

## Adding agents
With our newly setup policy, adding agents will be pretty straight forward. However, there are some slight differences when installing an agent on Windows or on Linux. They will be observed below.

1. From you policy page you want to install an agent from click on "Add agent"![Agents1.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Agents1.png)
2. This will bring up a drop down menu, we can skip over step one as we only have on enrollment token and leave the option "Enroll in Fleet" as is in step 2. In step 3, you are prompted to select your OS and architecture/installation method. Below, we'll go over the differences for Linux Vs. Windows.

### Linux
1. Select the architecture of your machine to retrieve the code you need to paste in to your host.![Agents2.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Agents2.png)
2. Copy all but the last line of the provided commands and paste them into a Linux host that you want to collect logs from.![Agents3.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Agents3.png)
3. Now grab the final line that would install the elastic agent. Append `--insecure` to the end of it. This is necessary as we are using our own TLS certificates without a CA. After appending insecure, run the command and follow the directions provided. Your command should look something like the following:
   
   `$ sudo ./elastic-agent install --url=https://<YOUR-SIEM-IP>:8220 --enrollment-token=RHVkZSwgZ28gZ2V0IHlvdXIgb3duIGNlcnRpZmljYXRlIHRva2VuISA+Oig= -- insecure`
4.  After completing this, back in your browser you'll see the following, indicating that you have successfully installed the agent.![Agents4.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Agents4.png)

### Windows

# Configuring Alerts
## What to Create Alerts On
The primary purpose of your SIEM should be to keep an eye on all of your machines. However, it is not reasonable to search for IOCs on **every** host that you connect. So you should create alerts to notify you when something should be investigated. This can be a hard thing to do and there are many ways to go about it. One thing is true regardless, your alerting rules will continue to grow and change over time. In my personal opinion, the best place to start is with the [MITRE ATT&CK framework](https://attack.mitre.org/). This is a framework that lists a knowledge base of known adversary tactics and techniques. For your specific setup, not all tactics will be applicable to you, such as T1201 (Password Policy Discovery). However, it is a good place to start. I do plan to update this guide as I test and create more alerts, however it is pretty bare bones for now. Below I've included some other sources that give good advice on creating alerts for your SIEM.
* [siem-alerts-types-and-best-practices](https://stellarcyber.ai/learn/siem-alerts-types-and-best-practices/)
* [siem-alert-guide](https://www.comparitech.com/net-admin/siem-alert-guide/)
## How to Create an Alert
The main point of an alert is to cause further action when a certain log or pattern of logs appear. In a traditional SOC this is where a playbook would run to automate the remediation process and or an analyst would jump in to investigate. For our purposes we will create an alert that appears on the alert page and prompts you to investigate. For our demonstrative purposes, we will create an alert for a failed linux authentication. 

1. On the home page click the three bars in the top left and go to Security > Alerts. ![Alert1.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert1.png)
2. On the Alerts page, click on the "Manage Rules" button in the top right.![Alert2.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert2.png)
3. On the Rule page click on the "Create rule" button in the top left. ![Alert3.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert3.png)
4. **NOTE:** *At this point depending on what you want to alert on your actions may differ.* In the "Select rule type" window, type "Elasticsearch query", then click the Elasticsearch box.![Alert4.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert4.png)
5. You'll then be brought to a query rule page and prompted to select a query type. This is up to your preference, in my situation I find "ES|QL" to be my preferred query language due to its powerful capabilities. Then enter in the query you would want to alert for. In my instance I'm using a very basic failed authentication query. Additionally I've selected my time field of choice to be @timestamp
   ```
   FROM logs-*
   | WHERE event.category : "authentication" AND event.outcome : "failure"
   ```
   ![Alert5.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert5.png)
6. Next, I've configured this query to run once every minute and alert to everyone for every instance found. **NOTE:** Sometimes alerting behavior can generate multiple lines. You can avoid alert fatigue be improving the schedule and the query itself. 
7. We'll skip adding an action for this example and jump on to the third and final step creating rule details. I have filled mine out as seen below, but these are free for you to customize as you see fit. ![Alert7.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert7.png)
8. Next click on "Create rule" then "Save rule" when you are asked if you want no actions with your alert.![Alert8.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert8.png)
9. Finally we'll be brought to the rule's page. To verify if the alert is working you can either stay on the newly created rules page and observe the alerts tab at the bottom or navigate over to the alerts page via the drop down on the left and observe from there. Next jump onto a host with an agent setup and fail an authentication. For example
   `$ su root`
   You should see the alert pop up which is verifying that the SIEM is on the lookout for you. ![Alert9.png](https://github.com/pietzersagal/Notes/blob/main/Images/Elastic_SIEM/Alert9.png)
10. Now you can click and investigate the alert and take whatever action you deem necessary. NOTE: For our instance, once you click on the alert details the status will switch to resolved. You may not want this for your specific installation.

Congratulations, you now have a fully working SIEM with Elastic search! Before you go about doing anything else, below you'll find some basic hardening that you can do specific to elastic. If you are interested in more alerts I'll later be posting all of my alert queries. I'll later update this with a link.

# Hardening
Here we'll be going over some admittedly basic hardening steps to do for your SIEM.

## Configuring the Firewall
Solely for accessing the SIEM you only need the following ports open:

| Port Number | Service        |
| ----------- | -------------- |
| TCP/9200    | Elastic Search |
| TCP/5601    | Kibana         |
| TCP/8220    | Fleet          |

You can drop all other traffic. However, if you access your server with ssh or have any other services that are running on the machine, make sure to add those to your firewall before dropping all other traffic and enabling the firewall.

## Kibana Hardening
Due to some left over permissions of us setting up our own certificate, we should make sure that all the files in `/etc/kibana` are only accessible to root:kibana. Run `ls -la /etc/kibana` and ensure that all files are owned by root with the kibana group and that there are no read permissions for you certificate files, especially your key. You can change owner and group permissions with 

`$ sudo chown root:kibana /etc/kibana/<filename-here>`

You can set the correct permissions for any file with the following command:

`$ sudo chmod 660 /etc/kibana/<filename-here>`
