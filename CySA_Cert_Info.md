**Notes takes from Dion training Udemy course**

# Section 2: Identify Security Types
* Cyber Security Analyst encompasses many roles such as:
	* Incident analyst or responder
	* cyber security specialist or technician
	* Cyber crime analyst
* Analyst typically have the role of a technician or specialist first for 2-4 years before becoming an analyst
* Analysts are responsible for
	* implementing and configuring security controls
	* working in a SOC or CSIRT
	* auditing security processes and procedures
	* Conducting risk assessments, vulnerability assessments, and penetration tests
	* Maintaining up to date threat intelligence
* Required abilities of a SOC
	* Authority to operate
		* organization policies and procedures is what grant this
		* Ex. shutting down a server
	* Have skilled and motivated people within the SOC
	* Incorporate processes into a single center
		* access management and incident management for example should be managed by the SOC
	* Equipped to preform incident response
	* Ability to protect itself and the entire organization
	* ability to distinguish relevant information
	* collaboration with other SOCs
* **Security controls
	* NIST 800-53
		* contains security controls and information regarding them.
		* created by the US government
	* ISO 27001
		* international alternative to the NIST 800-53, but costs money if you want to use it.
	* Controls
		* names not used by NIST 800-53, due to the fact that the controls are not mutually exclusive. They are used on the exam.
		+ Technical (Logical) controls
			+ A security control that is implemented as a system (hardware, software, or firmware)
		+ Operational control
			+ A security control that is implemented by people rather than systems
		+ Managerial controls
			+ A security control that provides oversight of the information system
				+ Ex. risk identification, giving insight to other controls via things like vulnerability scans
		+ Functional Types
			+ Preventative
				+ reduce the likelihood of an attack succeeding
			+ Detective
				+ identify or record attempts at intrusion
			+ Corrective
				+ eliminate or reduce impact of event
			+ Physical
				+ control that acts against in person intrusion attempts
			+ Deterrent
				+ discourages intrusion attempts
			+ Compensation
				+ substitutes for a principal or other control
			+ Responsive
				+ actively monitors for attacks or vulnerabilities and takes action to mitigate them before they cause damage

# Section 3 Threat Intelligence Sharing 

+ Security Intelligence
	+ process where data is generated and then collected, processed, analyzed, and disseminated to provide insights into the security status of information systems
+ Cyber Threat Intelligence
	+ Investigation, collection, analysis, and dissemination of information about emerging threats and threat sources to provide data about the external threat landscape
	+ Two forms
		+ narrative report
			+ bought and produced by threat analysts
		+ data feed
			+ lists of known bad indicators
+ Intelligence cycle
	+ Requirements (Planning and Direction)
		+ Sets out goals for the intelligence gathering effort
		+ Only focus on gathering intel relevant to you
		+ Only collect information that you are allowed to collect
	+ Collection (and processing)
		+ software tools are gathering the data which will later be processed.
			+ Ex. SIEM, network capture, etc.
		+ Data must also be normalized into a standard format
		+ We also have to consider the following categories for each source of intelligence
			+ Timeliness
				+ ensures the source is up to date
			+ Relevancy
				+ ensures the source matches your use case
			+ Accuracy
				+ ensures a source produces an effective result
			+ Confidence Level
				+ ensures a source produces qualified statements about reliability
				+ We actually grade this for example with the MISP Project
		+ Sources of information
			+ Proprietary
				+ Intelligence is provided as a commercial service
			+ Closed-Source
				+ Data from provider's own analysis and research
			+ Open-Source
				+ Available without a subscription
				+ Ex.
					+ US-CERT
					+ Virus-total
					+ SANS ISC Suspicious Domains
	+ Analysis
		+ Figuring out what the data means typically with the help of some sort of analysis automation like alerts or machine learning.
		+ Typically separated into 3 categories: known good, known bad, and unknown where unknown would need further analysis
	+ Dissemination
		+ Publish information produced by analysts to consumers who need it.
		+ Often broken up into levels of intelligence
			+ Strategic
				+ addresses board themes and objectives
			+ Operational
				+ addresses day to day priorities of managers and specialists
			+ Tactical
				+ informs real time decisions, for example a SIEM alert
		+ Threat intelligence sharing, *tbh I don't know why it's included here*
			+ Risk Management
				+ Identifies, evaluates, and prioritizes threats and vulnerabilities to reduce their negative impact
			+ Incident Response
			+ Vulnerability Management
				+ identifying, classifying, prioritizing, remediating, and mitigating software vulnerabilities
			+ Detection and Monitoring
				+ observing activity to identify anomalous patterns for further analysis
	+ Feedback
		+ Aims to clarify requirements and improve the collection, analysis and dissemination of information.
			+ Lessons learned
			+ Measurable success
			+ Evolving threat issues
+ ISAC: Information Sharing and Analysis Center
	+ non profit group set up to share sector specific threat intelligence and security best practices among its members

# Chapter 4 Classifying threats 
+ Known threats: any threat that can be identified using basic signature or pattern matching
+ Unknown threat: can't be identified based on a basic signature or pattern matching
	+ Known Unknowns: malware that contains techniques to circumvent signature-matching and detection
	+ Unknown Known: malware that is unknown to us but known by someone else
+ Commodity malware: malware that is for sale with the intended use for the buy to use it on someone else.
+ Threat Research
	+ Reputation Data: Blacklists of known threat sources. Ex. malware signatures, IP address ranges, and DNS domains
	+ Indicators of compromise: A residual sign that an asset is under attack or successfully attacked
		+ Indicator of Attack: A term used as evidence that there is an ongoing intrusion attempt
	+ Behavioral Threat Research: Term that refers to the correlation of IoC into attack patterns
		+ Ex. launching a DDoS, connecting to a C2, Data exfiltration etc.
+ Attack Frameworks
	+ Cyber Kill Chain
	+ MITRE ATT&CK
	+ Diamond Model of Intrusion Analysis: explores the relationship between adversary, capability, infrastructure, and victim
+ Indicator Management
	+ Structured Threat Information eXpression (STIX): standard terminology for IoCs and ways of indicating relationships between them that is part of the OASIS CTI framework
		+ expressed in JSON
		+ Most important for exam
	+ Trusted Automated eXchange of Indicator Information (TAXII): Protocol for supplying codified information to automate incident detection and analysis
	+ OpenIOC: Uses XML formatted files for supplying codified information to automate incident detection and analysis
	+ Malware Information Sharing Project (MISP): Server platform for cyber threat intelligence sharing.
		+ Proprietary format
		+ Supports OpenIOC definitions
		+ Can import/export STIX over TAXII
# Chapter 5 Threat Hunting
* Threat Modeling: Identifies and assesses the possible threat actors and attack vectors that post a risk to security
	* Three main areas to consider
		* Adversary Capability: A formal classification of the resources and expertise available to a particular threat actor
		* Attack Surface: The point that receives external connections or inputs/outputs that could potentially be exploited.
		* Attack Vector: A specific path that a threat actor gains unauthorized accesses.
* Threat Hunting: Detecting the presence of threats that have not been discovered by normal monitoring
	* Establish a Hypothesis: derived from threat modeling and is based on potential events with higher likelihood and impact
	* Profiling Threat Actors and Activities: The creation of scenarios that show how a prospective attacker might attempt an intrusion and what their objectives might be
* AbuseIPDB: Community database that keeps tracks of IPs reported for abusive behavior
# Chapter 6 Network Forensics
+ Switched Port Analyzer (SPAN): Allows for the copying of ingress and or egress communications from one or more switch ports to another
+ Flow Collectors
	+ NetFlow: Cisco developed means of reporting network flow information to a structured database
		+ provides metadata but not full packet captures
	+ Zeek: passively monitors network like a sniffer and only logs data of potential interest
		+ very good for reducing file sizes
		+ tab delimiter, JSON formatted
	+ Multi Router Traffic Grapher (MRTG): Creates graphs showing traffic flows by polling through SNMP
+ Domain Generation Algorithm (DGA): Method used by malware to evade block lists by dynamically generating domain names for C2 networks
+ Fast Flux Network
	+ Method used by malware to hide the presence of C2 networks by continually changing the host IP addresses in domain records using domain generation algorithms
+ Secure Recursive DNS Resolver: Allows one trusted DNS server to communicate with other trusted DNS servers to search for an IP address and return it to the client
	+ Counters Fast Flux Networks and DGAs
# Chapter 7 Appliance Monitoring
+ Blinding Attack: firewall is under-resourced and cannot log data fast enough, so some data is missed.
+ Firewalking: Reconnaissance technique to enumerate firewall configuration and attempt to probe hosts behind it.
+ Egress Filtering: Applies ACL rules to outgoing traffic to prevent malware from communicating to C2 servers.
+ Black Hole: Mitigating DoS or intrusion attack by silently dropping traffic
	+ Sinkhole: send off into a valid network for later analysis
+ IDS/IPS
	+ Snort: free and open source, paid for "oinkcode" which contains security signatures and such
	+ Zeek (Bro): open source with scripting engine
	+ Security Onion: open-source Linux-based platform for security monitoring, incident response, and threat hunting that bundles Snort, Suricata, Zeek, Wireshark, and Network Miner
# Chapter 8 Endpoint Monitoring
+ Endpoint tools
	+ Anti-virus
	+ HIDS/HIPS
	+ Endpoint Protection Platform (EPP): performs multiple tasks such anti-virus HIDS/HIPS, firewall, DLP, and file encryption
	+ Endpoint Detection and Response (EDR): collects system data and logs for analysis and to provide early detection of threats
	+ User and Entity Behavior Analytics (UEBA): A system that can provide automated identification of suspicious activity by user accounts and computer hosts
		+ Makes use of AI
+ Sandboxing:
	+ FLARE VM: runs windows binary on the system and see what the status is and all the different changes the malware is doing
		+ runs on top of windows
	+ Cuckoo: automatically run different malware samples and see what they do inside of a Linux, Mac, or Windows environment
	+ Joe Sandbox: A sandbox tool for malware samples, designed for security analysts
		+ Automates a lot of the process
+ 5 steps of a malware attack
	+ Downloader/ Dropper
		+ often just code that downloads the rest of the code
	+ Maintain access
	+ Strengthen access
	+ Actions on Objectives
	+ Concealment
+ System Behavior
	+ System Idle (PID 0)/System (PID 4): kernel-level binaries that are used as the parent of the first user-mode process
	+ Client Server Runtime Subsystem (csrss.exe): Manages low-level Windows functions and it is normal to see several of these running (as long as they are launched from %SystemRoot#\\System32 and have no parent)
	+ WININIT (wininit.exe): Manages drivers and services and should only have a single instance running as a process
	+ Services.exe: Hosts nonboot drivers and background services and should only have one instance running as a child of wininit.exe
		+ Lots of malware masquerades as this.
		+ Should be started by the SYSTEM, LOCAL SERVICE, or NETWORK SERVICE accounts
	+ Local Security Authority Subsystem (lsass.exe): Handles authentication and authorization services for the system, and should have a single instance running as a child of wininit.exe
	+ WINLOGON (winlogon.exe): Manages access to the user desktop and should have only one instance for each user session with the Desktop Window Manager (dwm.exe) as a child process in modern version of Windows
	+ USERINIT (userinit.exe): Sets up the shell (typically explorer.exe) and then quits, so you should only see this process briefly after log-on
	+ Explorer (explorer.exe): Typical user shell launched with the user's account privileges rather than SYSTEMS's which is likely to be the parent for all processes started by the logged on user
+ What makes a process suspicious?
	+ Unrecognized name
	+ A process with a similar name to a legit process, ex. svchost, should be scvhost
	+ Process without icon, version information, description, or company name
	+ Processes that are unsigned
	+ Process whose digital signature doesn't match the identified publisher
	+ Any process that doesn't have a parent/child relationship with a principal windows process
	+ Any process hosted by Windows utilities like Explorer, notepad, Task Manager, etc.
	+ Any process that is packed, highlighted in process explorer
+ What to do with a suspicious process
	+ Identify how the process interacts with the Registry and file system
	+ Ask how the process is launched
	+ Find if the file is launched from a system folder or a temp folder
		+ system folder are typically more trustworthy
	+ Ask what files are being manipulated by the process
	+ Find out if the process restores itself upon reboot or after deletion
	+ Ask if a system privilege or service get blocked if you delete the process
	+ Find if the process is interacting with the network
+ Malware Attribute Enumeration and Characterization (MAEC) Scheme: A standardized language for sharing structured information about malware that is complementary to STIX and TAXII to improve the automated sharing of threat intelligence
+ Yara: Multi-platform program running on Windows, Linux, and Mac for identifying, classifying, and describing malware samples
	+ Yara rules: test for matching certain string combinations within a given data source
# Chapter 9 Email Monitoring
+ Email headers can be manipulated in 3 areas
	+ Display From: Ex. Support \<support@hackerjoe.xyz>
		+ This can be manipulated to be something like: `support@hackerjoe.xyz <evilguy@badwebsite.au>`, a lot of clients won't show what is in the brackets
	+ Envelope From: Various labels hidden from mail client
	+ Received From/By: List of MTA (Mail Transfer Agents) that processed email
+ Methods of thwarting spoofing attacks
	+ Sender Policy Framework (SPF): DNS record identifying hosts authorized to send mail for the domain with only one being allowed per domain
	+ Domain Keys Identified Mail (DKIM): Proveds a cryptographic authentication mechanism for mail utilizing a public key published as a DNS record
	+ Domain-based Message Authentication, Reporting, and Conformance (DMARC): A framework for ensuring proper application of SPF and DKIM utilizing a policy published as a DNS record
		+ can be used with SPF, DKIM, or both
+ Cousin Domain: A DNS domain that looks similar to another name when rendered by a Mail User Agent (MUA)
+ Email Codes (the important ones as least)
	+ 220 -> Ready to receive mail
	+ 250 -> Acknowledgement of receiving mail
+ Secure/ Multipurpose Internet Mail Extensions (S/MIME): An email encryption standard that adds digital signatures and public key cryptography to traditional MIME communications
	+ For this to work a user must be issued a digital certificate containing his or her public key, also a private key
# Chapter 10 Configuring your SIEM (Review)
+ When configuring a SIEM for a company (because they'll have 1000s of endpoints) you should pick an choose which logs seem relevant to send to a SIEM
+ Be able to answer the five Ws from logs
+ Data normalization:
	+ Agent-based: data is normalized on a host and then sent over to the SIEM
	+ Listener/Collector: Host that is configured to push updates to the SIEM over a protocol like syslog or SNMP
	+ Sensors: Allows SIEMs to collect packet capture and traffic flow data from sniffers and sensors that are positioned across the network
	+ Connectors or Plug-ins: A piece of software designed to provide parsing and normalization functions to a particular SIEM
	+ Use UTC when sending logs
# Chapter 11 Analyzing your SIEM
+ Key Performance Indicators (KPIs): A quantifiable measure used to evaluate the success of an organization, employee, or other element in meeting objectives for performance.
+ Anomaly: Something has fallen out of our set of rules
+ Behavioral: Something has fallen out of our expected pattern
+ Trend Analysis: The process of detecting patterns within a data set over time, and using those patterns to make predictions about future events or to better understand past events. Here are some types of trend analysis:
	+ Frequency-based: Establishes a baseline for a metric and monitors the number of occurrences over time.
	+ Volume-based: Measures a metric based on the size of something, such as disk space used or log file size.
	+ Statistical Deviation: Uses the concept of mean and standard deviations to determine if a data point should be treated as suspicious
+ Sparse attack: An attack that is spread out over time or endpoints
+ Narrative-based Threat Awareness and Intelligence: A form of trend analysis that is reported in long-form prose to describe a common attack vector seen overtime
+ Windows Management Instrumentation Command-Line (WMIC): Program used to review log files on a remote Windows machine
# Chapter 12 Digital Forensics
+ Forensics Procedures
	+ Identification: Ensure the scene is safe and secure to prevent evidence contamination, and identify the scope of evidence
	+ Collection: Ensure authorization to collect evidence is obtained, and then document and prove the integrity of evidence as it is collected
	+ Analysis: Create a copy of evidence for analysis and use repeatable methods and tools during analysis
	+ Reporting: Create a report of the methods and tools used in the investigation and present detailed findings and conclusions based on the analysis
+ Legal Hold: Process designed to preserve all relevant information when litigation is reasonably expected to occur
+ Optimally a liaison is appointed to be the point of contact with law enforcement and legal issues
+ Forensic analysis code of ethics:
	+ Analysis must be performed without bias
	+ Analysis methods must be repeatable by third parties
	+ Evidence must not be changed or manipulated
+ Work Product Retention: Contractual method of retaining forensic investigators to protect their analysis from disclosure by the work product doctrine.
	+ In short analysis reports are held by whoever hired you and are not required to be shared with other parties.
+ Order of volatility (Essentially what order you should collect evidence in)
	+ Short term:
		+ CPU registers and cache memory
	+ RAM, routing tables, ARP cache, process table, temporary swap files
	+ Mass storage: HDD/SSD/flash drive
	+ Remote logging and monitoring data
	+ Physical configuration and network topology
	+ Archival media
	+ NOTE: Most of the windows registry is stored on the disk, but some keys like HKLM/Hardware are only stored in memory so analysis of the registry should be done via the memory dump
+ Forensics Tools
	+ EnCase: Digital forensics case management produce created by Guidance Software with built-in pathways or workflow templates that show the key steps in many types of investigation
	+ The Forensic Toolkit (FTK): Digital forensics investigation suite by AccessData that runs on Windows servers or server clusters for faster searching and analysis due to data indexing when importing evidence
	+ The Sleuth Kit: Open-source digital forensics collection of command line tools and programming libraries for disk imaging and file analysis that interfaces with Autopsy as a graphical user front-end interface
+ System Memory Image Acquisition: Process that creates an image file of the system memory that can be analyzed to identify the processes that are running, the contents of temporary file system, Registry data, network connections, cryptographic keys, and more
	+ Live acquisition: Capturing the contents o memory while the computer is running using specialist  hardware or software.
		+ Ex. Memoryze (FireEye) and F-Response TACTICAL
	+ Crash Dump: The contents of memory are written to a dump file when Windows encounters an unrecoverable kernel error
		+ Returns a mini dump file which may contain useful information but is not a full dump
	+ Hibernation File: File that is written to the disk when the workstation is put into a sleep state
		+ Easily detectable so malware will hide when this happens
	+ Pagefile: File that stores pages of memory in use that exceed the capacity of the host's physical RAM modules
		+ written to disk is nice, but it is just a few pages at a time
+ Disk Image Acquisition: Process that creates an image file of the system's disks that can be analyzed to identify current, deleted, and hidden files on a given disk
	+ Live acquisition: Captured while the disk is running
		+ useful if the drive is encrypted but running
	+ Static acquisition by Shutting Down: The computer is properly shut down through the OS and then the disk is acquired
		+ Some malware may detect this and perform anti-forensics by encrypting files and such
	+ Static acquisition by pulling the plug: No one has a chance to react to you doing that.
		+ Chance for memory corruption
	+ Physical Acquisition: Bit by bit copy of a disk that includes every non-bad sector on the target disk including deleted or hidden data.
		+ takes a while
	+ Logical Acquisition: Copies files and folders
		+ Quick but won't capture deleted files
	+ Write Blockers: Forensic tool to prevent the capture or analysis device or workstation from changing data on a target disk or media
+ Imaging Utilities: Software utility that conducts the disk imaging of a target
	+ dd (Disk Duplicator): Available on \*Nix systems
+ File Integrity Monitoring (FIM): Software that reviews system files to ensure that have not been tampered with.
+ Master File Table (MFT): NTFS table that contains metadata with the location of each file in terms of blocks/clusters
+ File carving: The process of extracting data from a computer when that data has no associated file system metadata
	+ Scalpel: Open source command line tool that is part of Sleuth Kit and is used for file carving on windows and linux
+ Chain of custody: The record of evidence history from collection, to presentation in court, to disposal
# Chapter 13 Network IOC
+ Traffic Spikes:
	+  DDOS indicators (You are the target):
		+ unexpected surge in traffic
		+ excessive number of TIME_WAIT connections in a load balancer / web server's state table
		+ High number of HTTP 503 errors
		+ Done with ICMP, HTTP, DNS, NTP
		+ Mitigations:
			+ Conduct real-time log analysis to identify patterns of suspicious traffic and redirect it to a black hole or sinkhole
			+ Use geolocation and IP reputation data to redirect or ignore suspicious traffic
			+ Aggressively close slower connections by reducing timeouts on affected servers
			+ Use caching and backend infrastructure to offload processing to other servers
			+ Utilize enterprise DDoS protection services, Ex: Cloudflare or Akamai
	+ Distributed Reflection DoS (DRDoS): Attacker dramatically increases the bandwidth sent to a victim during a DDoS attack by implementing an amplification factor
		+ occurs when the adversary spoofs the victims's IP address and tries to open connections with multiple servers, thus causing all servers to respond back to the victim
+ Beaconing: A means for a network node to advertise its presence and establish a link with other nodes.
	+ Can be legit (AP heartbeat) or illegitimate
	+ **For Exam**: be prepared for a question on this and to identify it based on a consistent time (every 3 seconds for example), in the real world this is not that case 
	+ Mitigation:
		+ For IRC: don't use IRC lmao
		+ For HTTP(S) beacons: Use an intercepting proxy at the network's edge
		+ For DNS: Look for IOCs like: Several queries being repeated when a bot is checking into a control server for more orders, look for commands sent within a request or response queries with larger packets (attackers will just break it into smaller packets then, so just put it back together)
+ P2P connections:
	+ Can offer IOC for a worm
	+ much less common than client-server communication
	+ ARP Spoofing/Poisoning: Occurs when an attacker redirects an IP address to a MAC address that was not its intended destination
		+ can be detected by an IDS
+ Rouge Device: An unauthorized device on a network
+ Well known ports: 0-1023
+ Registered ports: 1024-49151
+ Dynamic ports: 49152-the rest
+ Port IOC
	+ Dynamic ports used for long periods of time
	+ Non-standard port number used for an already established service
	+ mismatched port and service numbers
	+ Mitigations:
		+ Configure firewalls to allow only whitelisted ports to communicate on ingress and egress interfaces
		+ configuration documentation should list what ports are needed and thus you should block everything else
		+ block mismatched ports
	+ TCP **know these**
		+ 21 - ftp
		+ 22 - ssh
		+ 23 - telnet
		+ 25 - smtp
		+ 53 - dns
		+ 80 - http
		+ 110 - pop3
		+ 111 - rpcbind (Maps Remote Procedure Call services to port numbers in a UNIX-line environment)
		+ 135 - msrpc (Advertises what RPC services are available in a windows environment)
		+ 139 - netbios-ssn (NetBIOS Session Service which supports Windows file sharing with pre-windows 2000 version hosts)
		+ 143 - imap
		+ 443 - https
		+ 445 - microsoft-ds (supports windows file sharing on windows networks)
		+ 993 - imapS
		+ 995 - pop3S
		+ 1723 - PPTP (*Legacy* Point to Point Tunneling protocol for VPN protocol with weak security implementation)
		+ 3306 - mysql
		+ 3389 - rdp
		+ 5900 - vnc (Virtual Network Computing, remote access service which is open source and used across all systems)
		+ 8080 - http-proxy
	+ UDP **know these**
		+ 53 - dns
		+ 67 - dhcps (S is for server)
		+ 68 - dhcpc (C is for client)
		+ 69 - tfpt (Trivial ftp)
		+ 123 - ntp
		+ 135 - msrpc
		+ 137 - netbios-ns (NetBIOS Name Service which supports Windows File Sharign with pre-Windows 2000 version hosts)
		+ 138 - netbios-dgm (NetBIOS datagram service which supports Windows File sharing with pre-Windows 2000 version hosts)
		+ 139 - netbios-dgm (NetBIOS session service which supports Windows File sharing with pre-Windows 2000 version hosts)
		+ 161 - snmp (Agent port for Simple Network Management Protocol)
		+ 162 - snmp (Management station port for receiving snmp trap messages)
		+ 445 - netbios-ds (supports windows file sharing on windows networks)
		+ 500 - isakmp (Internet Security Association and Key Management Protocol that is used to set up IPsec tunnels)
		+ 514 - syslog
		+ 520 - rip (Routing Information Protocol)
		+ 631 - iip (Internet Printing protocol)
		+ 1434 - MS-SQL
		+ 1900 - upnp (Universal Plug and Play, used for autoconfiguation of port forwarding by game consoles and other appliances)
		+ 4500 - nat-t-ike (Used to setup IPsec traversal through NAT gateway)
+ Data Exfiltration (At least the ones that aren't obvious)
	+ Overt Channels: Use of FTP- instant messaging, p2p, email, and other obvious file and data sharing tools
	+ Explicit Tunnels: Use of SSH or VPNs to create a tunnel to transmit that data across a given network
		+ IOC
			+ Atypcial endpoints involved in tunnels due to their geographical location
+ Covert Channel: Communication path that allows data to be sent outside of the network without alerting any intrusion detection or data loss countermeasures
	+ transmitting data over a non-standard port
	+ encoding data in TCP/IP headers
	+ Segmenting data into multiple packets
	+ Obfuscating data using hex
	+ transmitting data in an encrypted format
	+ Mitigation
		+ Advanced intrusion detection and user behavior analytics tools are best, but won't detect everything
+ Covert Storage Channel: Utilizes one process to write to a storage location and another process to read from that location
+ Covert Timing Channel:  Utilizes one process to alter a system resource so that changes in its response time can signal information to a recipient process
# Chapter 14 Host Related IOC
+ Abnormal Process Behavior: Indicator that a legitimate process has been corrupted with malicious code for the purpose of damaging or compromising the system.
	+ Need a baseline to compare to
	+ Windows Tools
		+ sfc (System file checker): checks internal tools to make sure they are the proper programs
		+ Process monitor
		+ Process explorer
		+ tasklist
		+ PE explorer
	+ Linux Tools
		+ pstree
		+ ps
	+ Instead of malware injecting into DLLs, on linux the inject into .so (Shared Object) files
+ Memory Overflow: A means of exploiting a vulnerability in an application to execute arbitrary code or to crash the process (or with an on going memory leak to crash the system)
	+ You can then take the program and run it in a sandbox
+ Staging area: A place where an adversary begins to collect data in preparation for data exfiltration, such as temporary files and folders, user profile locations, data masked as logs, alternate data streams (ADS), or in the recycle bin
+ windows dir commands
	+ `dir /Ax` displays files of type x, for example `dir /AH` shows hidden files
	+ `dir /Q` displays who owns each file
	+ `dir /R` displays alternate data streams for a file
+ `df`: Linux command that tells how much disk space is being use d by all mounted file systems and how much space is available for each
+ `du`: Linux command that tells how much space each directory is using
+ Detecting Privilege escalation:
	+ Unauthorized sessions: certain accounts access devices or services that they should not
	+ Failed log-ons
	+ New Accounts
	+ Guest account usage
	+ Off-hours usage
+ Unauthorized software: One of the most obvious IOC
+ Prefetch File: A file that records the names of applications that have been run, as well as the date and time, file path, run count, and DLLs used by the executable
+ Shimcache: An application usage cache that is stored in the Registry as the key
+ Amcache: An application usage cache that is stored as a hive file
+ Persistence
	+ checking the registry
		+ windows: use regdump from sysinternals since it displays last modified time
		+ linux: you can use grep
		+ look for autorun keys:
			+ Run: Initializes its values asynchronously when loading them for the registry, aka no order
			+ RunOnce: Initializes its values in order when loading them from the registry, aka run in a specific order
		+ Look for modifications to registry entries for the system's running drivers and services 
		+ Malware might attempt to change file associations for EXE, BAT, COM, and CMD files which are located in the registry
		+ Check registry entries for recently used files
		+ compare with known good baseline
	+ Windows Task Scheduler
		+ Look for tasks you don't know about
	+ crontab
		+ Look for tasks you don't know about
# Chapter 15 Analyzing Application-related IOCs
+ Anomalous Activity
	+ Unexpected Outbound communication: Unapproved outbound network connections
	+ Unexpected Output: Unusual request patterns or response can be indicative of an ongoing or past attack
	+ Service Defacement
+ Service Interruptions
	+ Failed Application Services: service failed to start or halts abruptly
	+ Windows Tools: 
		+ Task Manger
		+ Services.mnc
		+ net start: via command line
		+ Get-Service: via powershell
	+ Linux Tools:
		+ cron
		+ systemctl
		+ ps
		+ (h)top
+ Application logs:
	+ DNS Event Log: Contains a log of all events for each time the DNS server handles a request to convert between a domain name and an IP address
	+ HTTP Access Log: HTTP traffic that encountered an error or traffic that matches some pre-defined rule set
	+ FTP Access Logs: FTP traffic events in a W3C extended log format
	+ SSH Access Log: Standardized type of lo that can provide basic client/server session information
	+ SQL Event Log: Event/Error log that records events with fields like data, time, and the action taken, such as server startup, individual database startup, database cache clearing, and database not starting or shutting down unexpectedly
+ `lastlog`: Retrieves the log-on history from the /var/log/lastlog file and displays the account name, the TTY, the remote host, and the last time the user was logged in
+ `faillog`: Linux command that displays log-on failures
+ VM forensics
	+ VM Introspection (VMI): Uses tools installed in the hypervisor to retrieve pages of memory for analysis
	+ Saved State Files: Files written during virtual machine suspension
	+ Persistent Data Acquisition: Acquiring data from persistent devices, such as virtual hard drives and other virtualized mass storage devices to an image-based format
	+ File carving can be used to retrieve files from virtual hard drives
	+ Configure VMs to send logs somewhere that will not be destroyed when the VM is
+ Mobile Forensics
	+ Data Collection
		+ Device is typically encrypted by default so make sure to get it unlocked
	+ Extraction and Analysis Methods
		+ Manual Extraction: Manually going through phone with someone documenting (recording with camera) what you are doing
		+ Logical Extraction: Using utilities to get data from the device, like from the cloud
		+ File System Extraction: Manually download all of the data off of the device
		+ Call data Extraction: Pulling data off of the SIM card
	+ Forensics software
		+ Cellebrite: Tool focuses on evidence extraction from smartphones and other mobile devices, including older feature phones, and from cloud data and metadata using a universal extraction device (UFED)
		+ Mobile Phone Examiner Plus (MPE+): created by the developers of FTK
		+ Encase Portable
	+ Carrier Provided Logs: Any records of device activity that can be acquired from the mobile device's service provider with the use of a warrant
	+ Some data has a very small data retention period like PII
# Chapter 16 Analyzing Lateral Movement and Pivoting IOCs
+ Pass the Hash: Network-based attack where the attacker steals hashed user credentials and uses them as-is to try to authenticate to that same network that hashed credentials originated on
	+ Mimikatz: Open-source application that allows users to view and save authentication credentials in order to perform pass the hash attacks
	+ Mitigation
		+ This is difficult to detect because the attacker is using a legitimate form of authentication
		+ antivirus will block software that allows mimikatz
		+ Restrict and protect high privileged domain accounts
		+ Restrict and protect local accounts with administrative privileges
		+ Restrict inbound traffic using the Windows Firewall to all workstations except for help-desk, security compliance scanners, and servers
+ Golden Ticket: A Kerberos ticket that can grant other tickets in Active Directory environment
	+ How it happens
		+ Attackers try to access NTDS.DIT file
		+ Attacker dumps NTDS.DIT exposing the Kerberos trust anchor and the krbtgt (Kerberos Ticket granting ticket hash)
		+ Response team resets credentials, but not the krbtgt
			+ **SO YOU SHOULD CHANGE THE krbtgt, twice in a short period of time**
		+ Attacker is now able to craft a golden ticket using the krbtgt hash
		+ Attacker uses golden ticket to assume admin rights/Attacker compromises the DC
+ Lateral Movement: Attacking something that might have access to get the privileges you might need
+ Pivoting: Using a compromised host as a platform from which to spread an attack to other points in the network
	+ utilize port forwarding
# Chapter 17 Incident Response Preparation
* Incident: The act of violating an explicit or implied security policy
* Frameworks:
	* NIST SP 800-61: 4 phases
	* Comptia Modle: 5 phases
* Incident response team/ Computer Security Incident Response Team (CSIRT):
	* Incident response manger
	* Security Analyst
		* Triage Analyst: works on the network during the incident, filters out alerts, performs ongoing monitoring and analysis
		* Forensic analyst: Tries to figure out what happened, pieces together information so that they can form a timeline
	* Threat Researcher: Provide threat context during the incident
	* Cross Functional Support: Other people. like management, technical experts, legal team
* Call List: predefined list of IR contacts in hierarchical order for notification and escalation
* Incident Form: Records the detail about the reporting of an incident and assigns it a case or job number
* Data Criticality: Essentially what data should you prioritize protecting
	* PII
	* Sensitive Personal Information (SPI): Information about a subject's opinions, beliefs, and nature that is afforded specially protected status by privacy legislation
		* This is things like religious beliefs, political opinions, sexual orientation, etc.
	* Personal Heath Information (PHI): Information that identifies someone as the subject of medical records, insurance records, hospital results, or laboratory test results
	* Financial Information
	* Intellectual Property
	* Corporate Information: Confidential data owned by a company like product, sales, marketing, legal, and contract information
	* High Value Asset: An information system that processes data critical to a mission essential function
* Communication Plan:
	* You want a out-of-band communication (sending data via a different path than typical)
	* contains when you are willing to escalate to someone else
	* essentially don't communicate via methods you think are compromised and know when to contact who and how you will do it
* Reporting Requirements
	* Notifications that must be made to affected parties in the event of a data breach, as required by legislation or regulation
* Business Continuity Plan: plans and processes used during a response to a disruptive event
	* Disaster Recovery Plan: a type of BCP for natural disasters
	* 7 major steps for craft a BCP
		* Develop a policy for contingency planning
		* Conduct a business impact analysis
		* Identify the preventative controls
		* Create recovery strategies
		* Develop the BCP
		* Test, train, and exercise the BCP
		* Maintain the BCP
* Training: Education to ensure employees and staff understand their role in incident response
* Testing: The practice exercise of incident response procedures
	* Table top exercise (TTX)
	* Penetration Test

# Chapter 18 Detection and Analysis
+ OODA Loop (Not on exam but important): Guide to help Incident responders think clearly during the "fog of war"
	+ Observe: Identify the problem or threat and gain an overall understanding of the internal and external environment
		+ Do quickly because you will loop back, you'll never have enough data to continue so you just must continue on with the loop
	+ Orient: Reflect on what has been found during the observations and consider what should be done next
	+ Decide: Make suggestions towards an action or response plan while taking into consideration all of the potential outcomes
	+ Act: Carry out the decision and related changes that need to be made in response to the decision
+ Defensive Capabilities:
	+ Detect: Identify the presence of an adversary and the resources at their disposal
	+ Destroy: Render an adversary's resources permanently useless or ineffective
	+ Degrade: Reduce an adversary's capabilities or functionality, perhaps temporarily
	+ Disrupt: Interrupt an adversary's communications or frustrate or confuse their efforts
	+ Deny: Prevent an adversary from learning about your capabilities or accessing your information assets
	+ Deceive: Supply false information to distort the adversary's understanding and awareness
+ Triage and categorization is done based on one of two approaches
	+ Impact based approach: A categorization approach that focuses on the severity of an incident, such as emergency, significant, moderate, or low
		+ severity is based on scope and cost
		+ This is usually preferred by the industry
		+ Types of impact
			+ Organizational Impact: affects mission essential function in which the organization cannot operate as intended
			+ Localized Impact: limited in scope to a single department
			+ Immediate Impact: based on direct caused incurred because of an incident
			+ Total Impact: measured based on the costs that arise both during and following the incident, including damage to the company's reputation
	+ Taxonomy-based approach: An approach that defines incident categories at the top level, such as worm outbreak, phishing attempt, DDoS, external host/account compromise, or internal privilege abuse
+ Incident classification: here are some metrics to classify an impact
	+ Data Integrity
	+ System process criticality: An incident that disrupts or threatens a mission essential business function
	+ Downtime
	+ Economic: incident creates a short or long term cost
	+ Data correlation: incident is linked to a specific TTP of known adversary groups with extensive capabilities
	+ Reverse Engineering: incident where capabilities of the malware are discovered to be linked to an adversary group
	+ Recovery Time
	+ Detection Time
# Chapter 19 Containment, Eradication, Recovery, and Post-incident Actions
+ Containment goals
	+ Ensure the safety and security of all personnel
	+ Prevent an ongoing intrusion or data breach
	+ Identify if the intrusion is the primary or secondary attack
	+ Avoid alerting the attacker that the attack has been discovered
	+ Preserve forensic evidence
+ Methods of Containment
	+ Isolation: A mitigation strategy that involves removing an affected component from a larger environment
	+ Segmentation: A mitigation strategy that achieves the isolation of a host or group of hosts using network technologies and architecture
+ Sensitization methods
	+ Cryptographic Erase (CE): erasing the media encryption key for a self-encrypting drive
	+ Zero-fill
		+ Not viable for SSDs
	+ Secure Erase (SE): manufacturer provided software sanitizes an SSD
	+ Secure Disposal: physical destruction of drives
+ Eradication Actions
	+ Reconstruction: restoring a system that has been sanitized using scripted installation routines and templates
	+ Reimaging: restoring a sanitized system using an image-based backup
	+ Reconstitution: restoring a system that cannot be sanitized using manual removal, reinstallation and monitoring processes. Has 7 steps
		+ Analyze processes an network activity for signs of malware
		+ Terminate suspicious processes and securely delete them from the system
		+ Identify and disable autostart locations to prevent processes from executing
		+ Replace contaminated processes with clean versions from trusted media
		+ Reboot the system and analyze for signs of continued malware infection
		+ For continued malware infection, analyse firmware and USB devices for infection
		+ If test are negative reintroduce the system to the production environment
+ Recovery: returning the systems to a known good state and improve on what caused the incident
+ Recovery Actions
	+ Patching: Installing a set of changes to ca computer program or its supporting data design to update, fix or improve it
	+ Permissions: All types of permissions should be reviewed and reinforced after a incident
	+ Logging: Ensures scanning, monitoring, and log retrieval systems are functioning properly following the incident
	+ System Hardening: The process of securing a system's configuration and settings to reduce IT vulnerability and the possibility of being compromised
		+ one of the most effective actions
		+ Uninstall anything you aren't using
		+ If you need it, patch it frequently
		+ Always restrict users to the least privilege
+ Post-Incidents Activities: Analysis of the incident and responses to identify procedures or systems that could be improved
	+ Report Writing: communicate information about the incident to a wide variety of stakeholders
	+ Incident Summary Report: written for a specific audience about the incident for their use
	+ Evidence Retention: preservation of evidence based upon the required time period defined by regulations if there is a legal or regulatory impact caused by an incident
+ Lessons Learned
	+ The Six Questions
		+ Who was the adversary?
		+ Why was the incident conducted?
		+ When did the incident occur?
		+ Where did the incident occur?
		+ How did the incident occur?
		+ What controls could have mitigated it?
	+ After-Action Report/Lessons Learned Report: A report providing insight into the specific incident and how to improve response processes in the future
+ Root Cause Analysis: Systematic process to identify the initial source of the incident and how to prevent it from occurring again
	+ Define and scope the incident
	+ Determine the casual relationships
	+ Identify an effective solution
	+ Implement and track the solution
# Chapter 20 Risk Mitigation
+ Risk Identification Process
	+ Enterprise Risk Management (ERM): The comprehensive process of evaluating, measuring, and mitigating the many risks that pervade an organization
	+ Information Security Risk Diagram: Everything can touch everything else in the diagram
		+ Frame: Establish a strategic risk management framework that is supported by decision makers at the top tier of the organization
		+ Assess: Identify and prioritize business processes and workflows
		+ Respond: Mitigate each risk factor through the deployment of managerial, operational, and technical security controls
		+ Monitor: Evaluate the effectiveness of risk response measures and identify changes that could affect risk management processes
	+ Measuring risk
		+ Quantitative methods: able to calculate in the dollars and cents
		+ Qualitative methods: Have an opinion on a risk, such as high, medium, and low
+ Conducting an assessment
	+ Business Continuity Loss: A loss associated with no longer being able to fulfill contracts and orders due to the breakdown of critical systems
	+ Legal Costs: A loss created by organizational liability due to prosecution (criminal law) or damages (civil law)
	+ Reputational Harm: A loss created by negative publicity and the consequential loss of market position or consumer trust
	+ System Assessments: The systematic identification of critical systems by compiling an inventory of the business processes and the tangible and intangible assets and resources that support those processes
	+ Mission Essential Function (MEF): A business or organizational activity too critical to be deferred for anything more than a few hours
	+ Threat and Vulnerability Assessment: An ongoing process of assessing assets against a set of known threats and vulnerabilities
+ Risk Calculation
	+ Single Loss Expectancy (SLE): metric to determine the expected frinancial loss froma single event
		+ SLE= AV * EF
		+ Asset Value (AV): Monetary value of the asset that is at risk
		+ Exposure Factor(EF): Percentage of loss that would result from a specific threat
	+ Annual Rate of Occurrence (ARO): (# of threat occurrence)/(# of years in the period)
	+ Annual Loss Expectancy (ALE): SLE * ARO = ALE
	+ Semi-Quantitative Method: Uses a mixture of concrete values with opinions and reasoning to measure the likelihood and impact of risk
+ Business Impact Analysis (BIA): A systematic activity that identifies organizational risks and determines their effect on ongoing mission critical operations 
	+ Maximum Tolerable Downtime (MTD): The longest period of time a business can be inoperable without causing irrevocable business failure
	+ Recovery Time Objective (RTO): The length of time it takes after an event to resume normal business operations and activities
	+ Work Recovery Time (WRT): The length of time in addition to the RTO of individual systems to perform reintegration and testing of a restored or upgraded system following an event
	+ Recovery Point Objective (RPO): The longest period of time that an organization can tolerate lost data being unrecoverable
+ Risk Prioritization: What should be done about a risk. 4 main things
	+ Risk mitigation: Reduce the risk to fit within the company risk appetite
		+ implementing controls
		+ most common on the exam
	+ Risk avoidance: Ceasing an activity that presents risks
		+ changing plans
	+ Risk transference: moving or sharing the responsibility of risk with another identity
		+ insurance
	+ Risk acceptance: determining that a risk fits within a risk appetite
		+ For low risk things, like an alien invasion
+ Risk Appetite: How much risk are you willing to accept
+ Return on Security Investment (ROSI): Metric to calculate whether a security control is worth the cost of deploying and maintaining it
	+ ROSI = ((ALE - ALEm(Annual Loss Expectancy with the mitigating control in place) - C (cost))) / C
+ Engineering Tradeoff: Assessment of the benefit of risk reduction against the increased complexity or cost in a system design or specification
+ Communicating Risk
	+ Risk Register: Document highlighting the results of risk assessments in an easily comprehensible format
	+ Exception Management: Formal process that is used to document each case where a function or asset is non-compliant with written policy and procedural controls

# Chapter 21 Frameworks, Policies, and Procedures
+ Enterprise Security Architecture (ESA): Framework for defining the baseline, goals, and methods used to secure a business
+ Prescriptive Framework: Framework that stipulates control selection and deployment
+ Maturity Model: Component of an ESA framework that is used to assess the formality and optimization of security control selection and usage and address any gaps
+ Risk-based framework: Framework that uses risk assessment to prioritize security control selection and investment
	+ NIST Cybersecurity Framework: Risk-based framework that is focused on IT security over IT service provision
		+ Framework core: Identifies five cybersecurity functions (Identify, Protect, Detect, Respond, and Recover) and each function can be divided into categories and subcategories 
		+ Implementation Tiers: Assess how closely core functions are integrated with the organization's overall risk management process and each tier is classed as Partial, Risk Informed, Repeatable, and Adaptive
		+ Framework Profiles: Used to supply statements of current cybersecurity outcomes and target cybersecurity outcomes to identify investments that is more productive in closing the gap in cybersecurity capabilities shown by comparison of the current and target profiles
+ Industry Frameworks
	+ Payment Card Industry Data Security Standard (PCI DSS): Set of security standards created by major credit card companies to help protect sensitive payment card information from fraud and data breaches
	+ Center for Internet Security (CIS): Nonprofit organization that provides a set of best practice guidelines and security controls in order to secure IT systems
	+ Open Web Application Security Project (OWASP): Nonprofit organization that aims to promote and improve web application security
	+ ISO 27000: Used to provide a framework for managing information security
		+ ISO/IEC 27001: A standard that specifies the requirements for an information security management system
	+ Open Source Software Testing Maturity Model (OSS TMM): A framework for evaluating and improving the quality of open source software and its testing processes
+ Audits and Assessments
	+ Quality Control (QC): Process of determining whether a system is free from defects or deficiencies
	+ Quality Assurance (QA): Processes that analyze what constitutes quality and how it can be measured and checked
	+ Verification: Compliance-testing process to ensure that the security system meets the requirements of a framework or regulatory environment, or that a product or system meets its design goals
	+ Validation: Process of determining whether the security system is fit for purpose
	+ Assessment: Process of testing the subject against a checklist of requirements against an absolute standard
	+ Evaluation: Less methodical process of testing that is aimed at examining outcomes or proving usefulness of a subject being tested
		+ more opinion based than an assessment
	+ Audit: Rigid process where an auditor compares the organization against a predefined baseline to identify areas that require remediation
	+ Scheduled Review: Similar to a lessons learned review, except it occurs at a regular interval, such as quarterly or annually
	+ Continual Improvement: Process of making small, incremental gains to products and services by identifying defects and inefficiencies for further refinement
+ Continuous Monitoring: The technique of constantly evaluating an environment for changes so that new risks may be quickly detected and business operations be improved upon
	+ Continuous Diagnostics and Mitigation (CDM): Provides US government agencies and departments with capabilities and tools to identify cybersecurity risks on an ongoing basis, prioritize these risks based upon potential impacts, and enable cybersecurity personnel to mitigate the most significant problems

# Chapter 22 Enumeration Tools
+ Enumeration: Process to identify and scan network ranges and hosts belonging to the target and map out an attack surface
+ Footprinting: Tools that map out the layout of a network, typically in terms of IP address usage, routing topology, and DNS namespace (subdomains and hostnames) 
	+ Fingerprinting: Tools that perform host system detection to map out open ports, OS type and version, file shares, running services and applications, system uptime, and other useful metadata
+ nmap: apparently you don't need to know the flags and this guy wasted my time
	+ `-sL`: Lists the IP addresses from the supplied target range(s) and performs a reverse DNS query to discover any host names associated with those IPs. Is more of a passive method since you don't directly interact with the hosts
	+ `-PS`: TCP SYN Ping, instead of ICMP Ping so host is more likely to respond
	+ `--scan-delay <Time>`: Issues probes with significant delays to become stealthier and avoid detection
	+ `-Tn`: Scan Timing, issues probes using a timing pattern with n being the pattern to utilize (0 is the slowest and 5 is the fastest)
	+ `-sI`: TCP Idle Scan, this scan makes it appear that another machine (a zombie) started the scan to hide the identity of the scanning machine
	+ `-f` or `--mtu`: Fragmentation, a technique that splits the TCP header of each probe between multiple IP datagrams to make it hard to detect
+ hping: open-source spoofing tool that provides a pentester with the ability to craft network packets to exploit vulnerable firewalls and IDS/IPS
+ Maltego: open-source tool that is widely used by cybersecurity analysts for data mining, reconnaissance, and enumeration
	+ has GUI
	+ identifies different relationships within a network
	+ tracks down identity and ownership
	+ analyze social media and provide it in a graphical tool
+ Responder: command-line tool used to poison responses to NetBIOS, LLMNR, and MDNS name resolution requests in an attempt to perform a man-in-the-middle attack
	+ works if host does not have access to the DNS server so the host will then ask it's neighbors. Responder will then hop in and answer accordingly
+ Reaver: Command-line tool used to perform brute force attacks against WPS-enabled access points
	+ WPS: Wifi Protected Setup, the thing where you press a button on your router and connect within 60 seconds

# Chapter 23 Vulnerability Scanning
+ Vulnerability Assessment: An evaluation of a system's security and ability to meet compliance requirements based on the configuration state of the system as represented by information collected from the system
	+ For exam remember: Scan -> Patch -> Scan
+ When scanning you need to be aware that some things like the firewall or IDS/IPS will likely block it cause a scanner imitates malicious traffic, here are some ways around that
	+ Schedule a time to disable these for the scans (not recommended)
	+ Put a scanner on each subnet (more expensive)
	+ Configure rules/exceptions for the scanners
+ Privileged Access Management (PAM) Solution: Can grant access for a limited time or until a task has been completed
	+ typically costs money
+ Vulnerability Feed: Synchronized list of data and scripts used to check for vulnerabilities, also known as plugins or network vulnerability tests (NVTs)
	+ typically costs money
	+ Uses SCAP
+ Security Content Automation Protocol (SCAP): Outlines various accepted practices for automating vulnerability scanning by adhering to standards for scanning processes, results reporting and scoring, and vulnerability prioritization
	+ Open Vulnerability and Assessment Language (OVAL): An XML schema for describing system security states and querying vulnerability reports and information
	+ Extensible Configuration Checklist Description Format (XCCDF): An XML schema for developing and auditing best-practice configuration checklists and rules
+ Compliance Scan: A scan based on a compliance template or checklist to ensure the controls and configuration settings are properly applied to a given target or host
	+ typically regulations tell you when to do them
	+ PCI DSS - quarterly scan

# Chapter 24 Analyzing Output from Vulnerability Scanners
+ Common Vulnerability Identifiers
	+ Common Vulnerabilities and Exposures (CVE): A commonly used scheme for identifying vulnerabilities developed by MITRE and adopted by NIST
	+ National Vulnerability Database (NVD): A superset of the CVE database, maintained by NIST, that contains additional information such as analysis, criticality metrics (CVSS), and fix information or instructions
	+ Common Weakness Enumeration (CWE): A list of software weaknesses of flaws that could potentially lead to vulnerabilities
	+ Common Attack Pattern Enumeration and Classification (CAPEC): A knowledge base maintained by MITRE that classifies specific attack patterns focused on application security and exploit techniques
	+ Common Platform Enumeration (CPE): Scheme for identifying hardware devices, operating systems, and applications
	+ Common Configuration Enumeration (CCE): Scheme for provisioning secure configuration checks across multiple sources
+ Common Vulnerability Scoring System (CVSS): A risk management approach to quantifying vulnerability data and taking into account the degree of risk to different types of systems or information
	+ Base Metrics
		+ Access Vector (AV): Does the Attacker need to have physical, local, adjacent network, or network
		+ Access Complexity (AC): High or low
		+ Privileges Required (PR): None, Low, or High
		+ User Interaction (UI): None or Required
		+ Scope(S): Unchanged or Changed
		+ Confidentiality (C): High, Medium, or Low
		+ Integrity (I): High, Medium, or Low
		+ Availability (A): High, Medium, or Low
+ Validate Scanner reports before accepting them
# Chapter 25 Mitigating Vulnerabilities
+ Remediation: The overall process of reducing exposure to the effects of risk factors
+ Center for Internet Security (CIS): A not-for-profit organization that publishes the well-known "Top 20 Critical Security Controls"
	+ Provides benchmarks and security templates that many people use
+ System Hardening: The process where a host or other device is made more secure through the reduction of that devices's attack surface area
	+ Remove or disable devices that are not needed or used
	+ Install OS, application, firmware, and driver updates frequently
	+ Uninstall all unnecessary network protocols
	+ Uninstall or disable all unnecessary services and shared folders
	+ Enforce ACL on all system resources
	+ Restrict user accounts to least privilege needed
	+ Secure the local admin or root account by renaming it and changing password
	+ Disable unnecessary default user and group accounts
	+ Verify permissions on system accounts and groups
	+ Install antimalware software and update its definitions regularly
+ Patch Management: Identifying, testing, and deploying OS and application updates
+ Remediation issues
	+ Is it financially worth it to remediate a risk
	+ Legacy Systems: find compensating controls
	+ Proprietary Systems
	+ Organizational Governance: System by which an organization makes and implements decisions in pursuit of its objective
		+ Hospitals prioritize healthcare and not security first
	+ Business Process Interruption: Period of time when an organization's way of doing operations is interrupted
	+ Degrading Functionality: Period of time when an organization's systems are not performing at peak functionality
	+ Memorandum of Understanding (MOU): Preliminary or exploratory agreement to express an intent to work together that is not legally binding and does not involve the exchange of money
	+ Service Level Agreement (SLA): Contractual agreement setting out the detailed terms under which an ongoing service is provided
# Chapter 26 Identity and Access Management Solutions
+ Identity and Access Management (IAM): Security process that provides identification, authentication, and authorization mechanisms for users and computers
+ Privilege Management: Use of authentication and authorization mechanisms to provide an administrator with centralized or decentralized control of user and group role-based privilege management
+ Access Controls
	+ Discretionary Access Control (DAC): each resource is protected by an ACL managed by the resource's owner(s)
		+ Windows
	+ Mandatory Access Control (MAC): resourced are protected by inflexible, system-defined rules where everey resources (object) and user (subject) is allocated a clearance level (or label)
		+ SE Linux
	+ Role-Based Access Control (RBAC): resources are protected by ACLs that are managed by administrators and that provide user permissions based on job functions
		+ Partially Windows
	+ Attribute-Based Access Control (ABAC): technique that evaluates a set of attributes that each subject possesses to determine if access should be granted
		+ good for separation of duties
+ Recertification: Manual review of accounts, permissions, configurations, and clearance levels at a given interval
+ Code of conduct: A defined set of rules, ethics, and expectations for employees in a particular job role
+ Privileged User Agreement (PUA): A contract with terms stating a code of conduct for employees is assigned based on their higher level permissions on the network and data systems
+ Acceptable Use Policy (AUP):  A policy that governs employees' use of company equipment and internet services
+ Federation
	+ Relying Parties (RPs) provide services for the federation
	+ Identity Provider (IdP): Provides the identities and releases information about those identities
# Chapter 27 Network Architecture and Segmentation
+ Request for Change (RFC): Document that lists the reason for a change and the procedures to implement that change
+ Network Architecture
	+ Physical Network: Refers to the cabling, switch ports, router ports, and wireless access points that supply cabled and wireless network access and connectivity
	+ Virtual Private Network: Secure tunnel created between two endpoints connected via an unsecure network, usually over the internet
	+ Software-Defined Networking (SDN): APIs and compatible hardware allowing for programmable network appliances and systems
		+ fully automated deployment
		+ Control Plane: Makes decisions about how traffic should be prioritized and secured, and where is should be switched
		+ Data Plane: Handles the actual switching and routing of traffic and imposition of ACLs for security
		+ Management Plane: Monitors traffic conditions and network status
	+ Secure Access Secure Edge (SASE): combines both network security and wide area network (WAN) capabilities into a single solution
+ Segmentation
	+ System Isolation (Air Gap): A type of network isolation that physically separates a network from all other networks
	+ Physical Segmentation: Each network segment has its own switch, an only devices connected to that switch can communicate with each other
	+ Virtual Segmentation: Network segmentation that relies on VLANs to create equivalent segmentation that would occur if physical switches are used
	+ Zones: The main unit of a logically segmented network where the security configuration is the same for all hosts within it
	+ Access Control Lists (ACL): A list of IP addresses and ports that are allowed or denied access to the network segment or zone
+ Screened Subnet: A segment isolated from the rest of the private network by one or more firewalls that accepts connections from the internet over designated ports
+ Bastion Hosts: Hosts or server in the screened subnet which are not configured with any services that run on the local network
+ Jumpbox: A hardened server that provides access to other hosts within the DMZ
+ Virtual Networks: Virtual hosts are interconnected using virtual switches, virtual routers, and other virtualized networking equipment as part of the hypervisor
+ Management Interface: Management application that is located wither on the physical host that runs the VMs or on a centralized platform that oversees VMs from multiple physical hosts
+ Honeypots
	+ Attribution: Identification and publication of an attacker's methods, techniques, and tactics as useful threat intelligence
+ Zero Trust
	+ Deperimeterization: The removal of a boundary between an organization and the outside world
# Chapter 28 Hardware Assurance Best Practices
+ Trusted Foundry: A microprocessor manufacturing utility that is part of a validated supply chain where hardware and software does not deviate from its documented function
	+ Created an operated by the DoD
+ Hardware Root of Trust (ROT): Cryptographic module embedded within a computer system that can endorse trusted execution and attest to boot settings and metrics
	+ For example a TPM
+ Trusted Platform Module (TPM): Specification for hardware-based storage of digital certificates, keys, hashed passwords, and other user and platform identification information
+ Hardware Security Module (HSM): Appliance for generating and storing cryptographic keys that is less susceptible to tampering and insider threats than software-based storage
+ Measured Boot: A UEFI feature that gathers secure metrics to validate the boot process in an attestation report
+ Attestation: A claim that the data presented in the report is valid by digitally signing it using the TPM's private key
+ eFUSE: A means for software or firmware to permanently alter the stat of a transistor on a computer chip
+ Secure Processing: A mechanism for ensuring the confidentiality, integrity, and availability of software code and data as it is executed in volatile memory
	+ Processor Security Extensions: Low-level CPU changes and instructions that enable secure processing
		+ AMD has Secure Memory Encryption (SME) and Secure Encrypted Virtualization (SEV)
		+ Intel has Trusted Execution Technology (TXT) and Software Guard Extensions (SGX)
	+ Trusted Execution: The CPU's security extensions invoke a TPM and secure boot attestation to ensure that a trusted operating system is running
	+ Secure Enclave: An extension that allows a trusted process to create an encrypted container for sensitive data
	+ Atomic Execution: Certain operations that should only be performed once or not at all, such as initializing a memory location
	+ Bus Encryption: Data that is encrypted by an application prior to being placed on that data bus
# Chapter 29 Specialized Technology
+ OT is a much different beast than IT
+ Enterprise Mobility Management (EMM): A mobile device management suite with broader capabilities such as identity and application management
+ Embedded Systems
	+ Programmable Logic Controller (PLC): A type of computer designed for deployment in an industrial or outdoor setting that can automate and monitor mechanical systems
	+ System-on-Chip (SoC): A processor that integrates the platform functionality of multiple logical controllers onto a single chip
	+ Field Programmable Gate Array (FPGA): A processor that can be programmed to perform a specific function by a customer rather than at the time of manufacture
+ Industrial Control System (ICS): A network that manages embedded devices, uses fieldbus
	+ Fieldbus: Digital serial data communications used in operational technology networks to link PLCs
	+ Human-Machine Interface (HMI): Input and output controls on a PLC to allow a user to configure and monitor the system
+ Data Historian: Software that aggregates and catalogs data from multiple sources within an industrial control system
+ Supervisory Control and Data Acquisition (SCADA): A type of industrial control system that manages large-scale, multi-site devices and equipment spread over a geographic region
	+ ICS is one plant, SCADA is multiple plants
+ Modbus: A communication protocol used in operational technology networks
	+ Used instead of TCP
+ Mitigating Vulnerabilities
	+ Establish administrative control over operational technology networks by recruiting staff with relevant expertise
	+ Implement the minimum network links by disabling unnecessary links, services, and protocols
	+ Develop and test a patch management program for Operational Technology networks
	+ Perform regular audits of logical and physical access to systems to detect possible vulnerabilities and intrusions
+ Premise System: Systems used for building automation and physical access security
+ Building Automation Systems (BAS): Have components and protocols that facilitate the centralized configuration and monitoring of mechanical and electrical systems within offices and data centers
+ Physical Access Control System (PACS): Components and protocols that facilitate the centralized configuration and monitoring of security mechanisms within offices and data centers
+ Vehicular Vulnerabilities
	+ Controller Area Network (CAN): A digital serial data communications network used within vehicles
		+ primary external interface is the OBD-II
		+ There's no concept of source addressing or message authentication in a CAN bus
		+ Exploiting the CAN
			+ Attach exploit to the OBD-II
			+ Exploit over onboard cellular (provided they are on the same network)
			+ Exploit over the onboard Wi-Fi
# Chapter 30 Non-technical Data and Privacy Controls
+ Data Classification: The process of applying confidentiality and privacy labels to a piece of information
	+ Data Governance: The process of managing information over its life cycle from create to destruction
+ Data Type: A tag or label to identify a piece of data under a subcategory of a classification
+ Data Format: The organization of information into preset structures or specifications
	+ Structured: Ex: First name, Last name, Address, ...
	+ Unstructured: Ex: chat log
+ Data State: The location of data within a processing system
	+ Data at rest
	+ Data in motion
	+ Data in use
+ Legal Requirements
	+ General Data Protection Regulation (GDPR): Personal data cannot be collected, processed, or retained without the individual's informed consent
		+ European law
	+ Sarbanes-Oxley Act (SOX): Sets forth the requirements for the storage and retention of documents relating to an organization's financial and business operations, including the type of documents to be stored and their retention periods
	+ Gramm-Leach-Bliley Act (GLBA): Sets forth the requirements that help protect the privacy of an individual's financial information that is held by financial institutions
	+ Federal Information Security Management Act (FISMA): Sets fort the requirements for federal organizations to adopt information assurance controls
	+ Health Insurance Portability and Accountability Act (HIPAA): Sets forth the requirements that help protect the privacy of an individual's health information that is held by healthcare providers, hospitals, and insurance companies
	+ Committee of Sponsoring Organizations of the Treadway Commission (COSO): Provides guidance on a variety of governance-related topics including fraud, controls, finance, and ethics, and relies on COSO's ERM-integrated framework
+ Purpose Limitation: The principle that personal information can be collected an processed only for a stated purpose to which the subject has consented
+ Data Minimization: The principle that only necessary and sufficient personal information can be collected and processed for the stated purpose
+ Data Sovereignty: The principle that countries and states may impose individual requirements on data collected or stored within their jurisdiction
+ Short term retention: how often the youngest media sets are overwritten
+ Long term retention: any data that is moved to an archive to prevent being overwritten
+ Data ownership
	+ Data owner: senior executive role with ultimate responsibility for maintaining the CIA of the information asset. Responsible for labeling the asset and ensuring that it is protected with appropriate controls
	+ Data steward: focused on the quality of the data and associated metadata
	+ Data custodian: responsible for handling the management of the system on which the data assets are stored. For example a system administrator
	+ Privacy officer: responsible for the oversight of any PII/SPI/PHI assets managed by the company
+ Data Sharing
	+ Service Level Agreement (SLA): A contractual agreement setting out the detailed terms under which a service is provided
	+ Interconnection Security Agreement (ISA): An agreement used by federal agencies to set out a security risk awareness process and commit the agency and supplier to implementing security controls
	+ Non-Disclosure Agreement (NDA): A contract that sets forth the legal basis for protecting information assets between two parties
	+ Data Sharing and Use Agreement: An agreement that sets forth the terms under which personal data can be shared or used
# Chapter 31 Technical Data and Privacy Controls
+ File Permissions
	+ icacls: A windows command-line tool for showing and modifying file permissions
+ DLP agent actions
	+ Alert only
	+ Block: User is prevented from copying a file
	+ Quarantine: Access is removed from user or all users
	+ Tombstone: File is replaced with another stating the DLP policy has been violated
+ DLP Discovery and Classification
	+ Classification: A rule based on confidentiality classification tag or label attached to the data
	+ Dictionary: A set of patterns that should be matched
	+ Policy Template: A template that contains dictionaries optimized for data points in a regulatory or legislative schema
	+ Exact Data Match (EDM): A structured database of string values to match
	+ Document Matching: Matching based on an entire or partial document based on hashes
	+ Statistical/Lexicon: A further refinement of partial document matching which uses machine learning to analyze a range of data sources
+ Deidentification: removing identifying information
	+ Data masking: generic or placeholder labels are substituted for real data while preserving the structure or format of the original data
	+ Tokenization: a unique token is substituted for real data
	+ Aggregation/Banding: data is generalized to protect the individuals involved
+ Digital Rights Management (DRM): Copyright protection technologies for digital media which attempts to mitigate the risk of unauthorized copies being distributed
	+ can be protected via hardware (region locking for examples) or software (have to view on the website)
	+ Also note watermarking
# Chapter 32 Mitigate Software Vulnerabilities and Attacks
+ Software Development Life Cycle (SDLC): The process of planning, analysis, design, implementation, and maintenance that governs software ans systems development
	+ Security-targeted frameworks incorporate threat, vulnerability, and risk-related controls within the SDLC
		+ Security Development Life Cycle (SDL): Microsoft's security framework for application development that supports dynamic development processes
		+ OWASP Software Security Assurance Process: OWASP's security framework for secure application development
+ Heap Overflow: Software vulnerability where input is allowed to overwrite memory locations within the area of a process' memory allocation used to store dynamically-sized variables
+ Address Space Layout Randomization (ASLR): Technique that randomizes where components in a running application are placed in memory to protect against buffer overflows
+ Dereferencing: Software vulnerability that occurs when the code attempts to remove the relationship between a pointer and the thing it points to
	+ Dirty CoW
+ Time of Check to Time of Use (TOCTTOU): Potential vulnerability that occurs when there is a change between when an app checked a resource and when the app used the resource
	+ Develop apps to not process things sequentially if possible
	+ Implement a locking mechanism to provide app with exclusive access
+ Design Vulnerabilities
	+ Insecure Components: Any code that is used or invoked outside the main program development process
	+ Insufficient Logging and Monitoring: Any program that does not properly record or log detailed enough information for an analyst to perform their job
	+ Weak/Default Configuration
# Chapter 33 Mitigate Web Application Vulnerabilities and attacks
+ XML Bomb (Billion Laughs Attack): XML encodes entities that expand to exponential sizes, consuming memory on the host and potentially crashing it
+ XML External Entity (XXE): An attack that embeds a request for a local resource
+ Normalization: A string is stripped of illegal characters or substrings and converted to the accepted character set
+ Canonicalization Attack: Attack method where input characters are encoded in such a way as to evade vulnerable input validation measures
+ Output Encoding: A coding method to sanitize output by converting untrusted input into a safe form where the input is displayed as data to the user without executing as code in the browser
+ Parameterized Queries: A technique that defends against SQL injection and insecure object references by incorporating placeholders in an SQL query
+ On-path Attack: Man in the middle
+ Credential Stuffing: Brute force attack in which stolen user account names and passwords are tested against multiple websites
+ Session Prediction Attack: A type of spoofing attack where the attacker attempts to predict the session token to hijack a session
+ Cookie Poisoning: Modifies the contents of a cookie after it has been generated and sent by the web service to the client's browser so that the newly modified cookie can be used to exploit vulnerabilities in the web app
+ Server-Side Request Forgery (SSRF): A type of cyber attack in which an attacker is able to send a request on behalf of a web application
+ Sensitive Data Exposure: A software vulnerability where an attacker is able to circumvent access controls and retrieve confidential or sensitive data from the file system or database
+ Clickjacking: A type of hijacking attack that forces a user to unintentionally click a link that is embedded in or hidden by other web page elements
# Chapter 34 Analyzing Application Assessments
+ Formal Verification Method: The process of validating software design through mathematical modeling of expected inputs and outputs
+ User Acceptance Testing (UAT): Beta testing by the end users that proves a program is usable and fit for purpose in real world conditions
+ Security Regression Testing: The process of checking that updates to code do not compromise existing security functionality or capability
+ Immunity Debugger: A debugger built specifically for penetration testers to write exploits, analyze malware, and reverse engineer binary files using Python scripts and APIs
+ SearchSploit: A tool used to find exploits available in the Exploit-DB
+ Arachni: Open-source web scanner with a GUI
# Chapter 35 Cloud and Automation
+ Cloud Deployment Model: Classifying the ownership and management of a cloud as public, private, community, or hybrid
	+ public: A service provider makes resources available to the end users over the internet. No physical control over the server
		+ Ex: AWS
	+ private: Company creates its own cloud environment that only it can utilize as an internal enterprise resource. Security is more important than cost. It is a single tenant model.
		+ Ex: AWS GovCloud
	+ community: Uses shared resources and costs among different organisations that have common service needs. Security depends on the cooperability of all organisations
		+ Ex: 5 different banks create a community cloud since they have similar needs
	+ hybrid: Combines different kinds of cloud deployment models
	+ Mulit: Uses multiple different cloud models at the same time
+ Cloud Service Model: Classification of the provision of cloud services and the limit of the cloud service provider's responsibility as either software, platform, infrastructure, etc.
	+ IaaS: like Microsoft 360
	+ PaaS: vendor gives you a machine with an operating system and will maintain it, like cyberrange
	+ SaaS: Vendor lets you control resources down to the operating system
+ Virtual Private Cloud: Segmented of cloud architecture kind of like a VPN
+ Cloud Access Security Broker (CASB): Enterprise management software designed to mediate access to cloud services by users across all types of devices. They do the folllowing:
	+ SSO
	+ Malware and rogue device detection
	+ Monitor/audit user activity
	+ Mitigate data exfiltration
# Chapter 36 Service-Oriented Architecture
+ Service Oriented Architecture (SOA): A software architecture where components of the solution a re conceived as loosely coupled services not dependent on a single platform type or technology
	+ Built from services with interdependencies
+ A common component of SOA architecture that facilitates decoupled service to service communication
+ Microservices: A software architecture where components of the solution are conceived as highly decoupled services not dependent on a single platform type or technology
	+ developed, tested, and deployed independently
+ Simple Object Access Protocol (SOAP): An XML-based web services protocol that is used to exchange messages
	+ Coercive Parsing: An attack that modifies requests to a SOAP web service in order to cause the service to parse the XML-based requests in a harmful way
+ Security Assertions Markup Language (SAML): XML-based data format used to exchange authentication information between a client and a service
	+ provides SSO and federated identity management
+ Representational State Transfer (REST): A software architectural style that defines a set of constraints to be used for creating web application services
	+ OAuth: A delegated authorization framework for RESTful APIs that enables apps to obtain limited access (scopes) to a user's data without giving away a user's password
		+ Clients: Applications that the user wants to access or use
		+ Resource Owners: End users being serviced
		+ Resource Servers: Servers provided by a service that the user wants to access
		+ Authorization Servers: Servers owned by the IdP
		+ Authorizes claims and not users, authorizes not authenticates
	+ OpenID Connect (OIDC): An authentication protocol that can be implemented as special types of OAuth flows with precisely defined token fields
	+ JSON Web Tokens (JWT): A token format that contains a header, payload, and signature in the form of a JSON message
+ Webhooks: one application can provide other applications with real-time information
	+ Server is always pushing data to the client
	+ Alternative to APIs since in APIs, software will request data when needed
+ Orchestration: The automation of multiple steps in a deployment process. Here are some tools
	+ Chef: A way to automate configuration deployments and management of applications
	+ Ansible: Does not use user agents since everything is done using YAML
	+ Docker
	+ Kubernetes: Provides an abstraction layer from managing these containers
	+ Github: Service that a lot of developers use to share their code
+ Function as a Service (FAAS): A cloud service model that supports server-less software architecture by provisioning runtime containers in which code is executed in a particular programming language
	+ Essentially just running code, you don't get a server
	+ For example Netfilx is FAAS
	+ For cyber people you now only have to monitor for the people that update the code are safe
# Chapter 37 Cloud Infrastructure
+ Cloud threats
	+ Insecure APIs: not being used to HTTPS, should have input validation, Error handling and error messaging, should have rate-limiting mechanisms
	+ Improper key management: You should use proper authentication and authorization
	+ Logging and monitoring: Cloud should have proper and meaningful logs, however not always available with SaaS
	+ Unprotected Storage: have a CORS policy
		+ Cross Origin Resource Sharing (CORS) policy: A content delivery network policy that instructs the browser to treat requests from nominated domains as safe
+ Cloud Forensics: Hard because you most of the time do not have access to the physical machine and is limited by the SLA. Instances are created and destroyed very quickly. There can be issues with chain of custody
+ Cloud Auditing:
	+ Scout Suite: An open-source tool written in Python that can be used to audit instances and policies created on multi-cloud platforms by collecting data using API calls
	+ Prowler: An open-source security tool used fro security best practice assessments, audits, incident response, continuous monitoring, hardening, and forensics readiness for AWS cloud services. Command line tool
	+ Pacu: An exploitation framework used to assess the security configuration of an AWS account
	+ CloudBrute: Used to find a target's infrastructure, files, and apps across the top coud service providers, including Amazon, Google, Microsoft, DigitalOcean, Alibaba, Vultr, and Linode
	+ Cloud Custodian: An open-source cloud security, governance, and management tool designed to help admins create policies based on different resource types
# Chapter 38 Automation Concepts and Technologies
+ DevOps: An organizational culture shift that combines software development and systems operations by referring to the practice of integrating the two disciplines within a company
+ DevSecOps: The addition of a security team to the Developer and Operations teams
+ Infrastructure as code (IaC): A provisioning architecture in which deployment of resources is performed by scripted automation and orchestration
	+ Snowflake Systems: Any system that is different in its configuration compared to a standard template within an infrastructure as code architecture
	+ Idempotence: A property of IaC that an automation or orchestration action always produces the same result, regardless of the component's previous state
+ Artificial Intelligence (AI): The science of creating machines with the ability to develop problem solving and analysis strategies without significant human direction or intervention
+ Machine Learning (ML): A component of AI that enables a machine to develop strategies for solving a task given a labeled dataset where features have been manually identified but without further explicit instructions
+ Artificial Neural Network (ANN): An architecture of input, hidden and output layers that can perform algorithmic analysis of a dataset to achieve outcome objectives
+ Deep Learning: A refinement of machine learning that enables a machine to develop strategies for solving a task given a labeled dataset and without further explicit instructions
+ Data Enrichment: The process of incorporating new updates and information to an organization's existing database to improve accuracy
+ Security Orchestration Automation, and Response (SOAR): A class of security tools that facilitates incident response, threat hunting, and security configuration by orchestrating automated runbooks and delivering data enrichment
	+ Runbook: An automated version of a playbook that leaves clearly defined interaction points for human analysis
+ Standardization: Process of establishing a set of consistent and repeatable guidelines, procedures, and best practices for security operations
+ Single Pane of Glass: A central point of access for all the information, tools, and systems