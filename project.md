Proactive Project

# **Simulate Malware Execution:**

We are using a Windows 10 Enterprise Virtual Machine on Virtual Box

![](media/62e5f1e4c01603de3f6fc26ab984d796.png)

Here we have the **ZEUS malware** before we run the malware, we will open **Wireshark** and start capturing the packets to further analysis.

![A screenshot of a computer Description automatically generated](media/b30d9f949ff5144cc1e2162d3e4795c8.png)

After Running it a UAC pops and requires changes approval from Adobe Flash Player. It doesn’t matter if we click yes or no it will do the same because if we clicked no, the UAC window will reappear.

![A screenshot of a computer Description automatically generated](media/ed4a572e22f517a496ba944039a0e933.png)

If we click on retry it will just reload and fail again.

Finally, the malware disappears from the desktop and the flash player tries to connect to something but fails.

## **Basic Conclusion:**

\- Has Anti-VM capabilities

\- Dropped an executable

\- Deleted / Moved the main executable

# **Configure Suricata for Network Monitoring:**

![](media/9e119482324c90c44f96ca8b7be115dc.png)

After Installing Suricata we went to its directory specifically suricata.yaml file to uncomment the default rules and we downloaded a collection of rules in one file called [emerging-all.rules](https://rules.emergingthreatspro.com/open/suricata-7.0.3/emerging-all.rules) to work with in our project.

We opened the captured packets to check its behavior using **Wireshark**

![](media/4acb01bfd7d69f436d6155ca0585d9bc.png)

When analyzing the packets using Wireshark, I noticed that the malware sends a malformed DNS request to 85.114.128.127.

![A screenshot of a computer Description automatically generated](media/c76856099b7600300d1aea07b011ae54.png)

When searching for it on Virus Total It was flagged as safe, but by noticing the files that communicates with this Ip I knew It was malicious.

![](media/048aa9cb434219f1f42f7122571a1096.png)

By knowing this I made a Suricata rule to alert when connecting to that IP and adding it to the suricata.yaml file.

![](media/4d812cd6986631c34847e8d2e64e0b0f.png)

So, by using these commands I used the suricata.yaml file as the config file and I listened on my ip address and made the logs dumps into the log folder and finally

\--service-install: to add it as a service to run on startup.

**Integrate with Splunk:**

![A screenshot of a computer Description automatically generated](media/2fa416b511e3030d0903423c50b1b855.png)

Now we need to forward these alerts to Splunk for centralized analysis.

We started by configuring the main server to send the alerts on using this path:

C:\\Program Files\\SplunkUniversalForwarder\\etc\\system\\local\\outputs.conf

***

![A close-up of a computer screen Description automatically generated](media/a5afdbf37e177638cd3d0aa17a868720.png)

Suricata appends detailed event logs to fast.log in real-time, enabling Splunk to ingest and analyze security events promptly.

![A screenshot of a computer Description automatically generated](media/ef5741920d041b3e8f5869550cf512b0.png)

We go to settings then forwarding and receiving

![A screenshot of a computer Description automatically generated](media/9350c9233802c3843d3839684f5338d8.png)

Then we add a new receiving to listen on port 9997

![A screenshot of a computer Description automatically generated](media/53235aeebe031dc064fb1d0e68941fbe.png)

Then we go to settings/index and create a new index to isolate Suricata events.

![A screenshot of a computer Description automatically generated](media/f626d39078843a4be6d386faeade74b8.png)

Then we go to search for ZEUS from Suricata index

![A screenshot of a computer Description automatically generated](media/08dabaaa93c0f9e2809ed9316ba4e4b0.png)

Then we will save it as an alert.

![A screenshot of a computer Description automatically generated](media/e2c506a4a58a8edb5c1baebd155428ba.png)

![A screenshot of a computer Description automatically generated](media/3d550c7dcfd4e99580194108b0dc526a.png)

Here we can show the alerts we wrote for now.

![A screenshot of a computer Description automatically generated](media/6b46309685a12801f6b892fefa2dc176.png)

![A screenshot of a computer Description automatically generated](media/c95d544c0149ea8cd0ba70b59b482cf9.png)Next, we executed the malware again to identify any triggered alerts.

We audit the **Users** folder to the windows event logs of any file creations or deletions

![A black and white screen with white text Description automatically generated](media/126439d22ff3bd00dab38c96d95803a8.png)

Event ID 4663: Indicates an attempt to access an object, such as file creation, modification, or deletion.

After some investigation we found that the malware adding files in temp we can confirm it using the event code above.

![A screenshot of a computer Description automatically generated](media/062223fca4df6b7102d285c087964ebf.png)

A thorough examination of the temporary directory revealed that the malicious invoice.exe executable had dropped falshplayer.exe, with the intent of launching it.

![A screenshot of a computer Description automatically generated](media/f4b0c04432f955a5a54a6106f65bc0f1.png)

Now we searched for this file in any path to find out if this file manipulates any process

![A screenshot of a computer Description automatically generated](media/e38b402bbad9ecdac887f7314968e384.png)

![A screenshot of a computer Description automatically generated](media/630564a192e2321f413111e6cef7270e.png)

Finally, we make this query to create a dashboard

![A screenshot of a computer Description automatically generated](media/cbfd20a67e9a1d604321c53e9404ed5b.png)

![A screenshot of a computer Description automatically generated](media/48b4579882778bea98ea7c488ce5bcbc.png)

Queries to create this dashboard.

**Volatility & Yara Rules**

**Working on the memory dump that you provided to us on classroom** <https://drive.google.com/file/d/1WnlYaVaDUi83Yvw7ER9j80pcXifnCQbW/view>

**I’ll be working on Volatility Workbench (GUI Volatility) and Volatility 2**

First, we need to list all processes we’ve got using (pslist and pstree) volatility plugins

**![A screenshot of a computer program Description automatically generated](media/874e0d8bd9022c2871c1f5d8f688fd58.png)pslist**

**![A screenshot of a computer screen Description automatically generated](media/9c8c743654bcdaafe24f32db27426d46.png)**

**pstree**

We can see from the process tree there’s a sql server and there’s a VM running on the system on startup (sqlserver.exe),(prl_tools.exe) which Parallels Tools for the running VM.

And some services for running it, in addition to some dll’s

These are the cmd command and the full path for all these processes that we talked about

![A close-up of a computer code Description automatically generated](media/74f8222fa0a545a021ab0fa37f368044.png)

Nothing really seems suspicious to me till now

![A screenshot of a computer code Description automatically generated](media/57cd70b57ae3120dcc15c2a7d758dab2.png)So, let’s see and investigate the next processes block (that have a fresh start process tree)

We can see there’s a process for Immunity Debugger that has been executed from the explorer, and then it opened another application that has a very suspicious name (b98679df6defbb3), and this suspicious process executed another process (vaelh.exe).

Each time Immunity Debugger executes, it executes another suspicious process.

We need to see the full name and the full path of these processes

![A screenshot of a computer program Description automatically generated](media/99c805ae2f4aa5bf7cd08beaf2db0fab.png)

![A screenshot of a computer Description automatically generated](media/286cdf50628a6267d0350652bf0a3f81.png)We can see the full name and path for the executed programs, there’s one of them that has a long alphanumeric name that seems like a hash (**b98679df6defbb3dc0e12463880c9dd7**.exe) Let’s check if it’s a valid hash or not using hash analyzer online tool <https://www.tunnelsup.com/hash-analyzer/>:

Now we are sure that the process name is a valid MD5 hash, Let’s check [Virustotal](https://www.virustotal.com/gui/file/659e4e7d8e33a9945b228c60d31f3924212126ecd2a2604baf28c7539a4d4230)

![A screenshot of a computer Description automatically generated](media/4113d5f38d3ffcdb4c17f30ccc9dc5f0.png)

**There won't be a clear way to confirm if it's harmful or not such as Virustotal score.**

Now let’s dump the process and make a quick investigation into it

![A screenshot of a computer Description automatically generated](media/79a7f722ba879b2825eb6fd1eba96d4f.png)

Using Exiftool on it to see the metadata of the file

![A screenshot of a computer Description automatically generated](media/fb587b714f46e5704d151e41bf75812c.png)

We can see these attributes are not specific or even written using an appropriate English language so it’s more suspicious to be malicious, we can see the original file name is the same file name we see on [virustotal](https://www.virustotal.com/gui/file/659e4e7d8e33a9945b228c60d31f3924212126ecd2a2604baf28c7539a4d4230) (**Ydeku**).

![A screenshot of a computer code Description automatically generated](media/57cd70b57ae3120dcc15c2a7d758dab2.png)Now let’s return to this image and analyze the rest suspicious files that are child processes for this malicious file:

![A screenshot of a computer program Description automatically generated](media/7177ea89adc048e0591dd29ea2314515.png)Now Let’s Dump (**ihah.exe**) and investigate it:

Also, another random characters that doesn’t represent a name at all.

![A screenshot of a computer Description automatically generated](media/512db8bf62d87710ebfa2b3b7dd97273.png)The original name of the file (**Axumexupleopikoft**) that we got from Exiftool, is the same as shown in [virustotal](https://www.virustotal.com/gui/file/659e4e7d8e33a9945b228c60d31f3924212126ecd2a2604baf28c7539a4d4230).

![A screenshot of a computer code Description automatically generated](media/57cd70b57ae3120dcc15c2a7d758dab2.png)And so on for all other files, all of them has a High Community Score and seems to be malicious

![A screenshot of a computer Description automatically generated](media/e130f29fe3fbb17d69a0af4635bdc815.png)

**vaelh.exe  
Analysis :**

Based on the information from the metadata of the (**vaelh.exe**) file we can see that it doesn’t seem suspicious , whether virustotal has a high score to me malicious,

But virustotal has a high score based on 57 security vendors that flagged this as a malicious file, whether it seems that it has a valid File Description, Company name, legal copyright, product name. As shown in the following image it seems that it’s packed with UPX

**![A screenshot of a computer Description automatically generated](media/0a7692228dd6751823033d92aab3a385.png)**

We can see it also from Detect it easy that it’s packed with UPX and has a high entropy in the code which means that the file contains data that appears highly random or lacks recognizable patterns. (Entropy is a measure of uncertainty or randomness in data)

![A screenshot of a computer screen Description automatically generated](media/e06fcafceb174d42035d1e4a8bc63927.png)![A screenshot of a computer Description automatically generated](media/9a66618c038de4ab8e7e3ed0e8718bb1.png)

![A screenshot of a computer Description automatically generated](media/b11d714f4db310be0b00c7647a86bed8.png)

**anaxu.exe  
Analysis:**

![A screenshot of a computer Description automatically generated](media/747924586b3009d55f5a00cdaeea7d53.png)Seems so suspicious to me, let’s check virustotal also:

**NOTE:** I didn’t use (**windows.malfind**) plugin as it’s not precise also, all files that I scanned above **malfind** found in addition to a lot of other false positive files, so I don’t recommend using it.

All these files that we scanned were malicious, so let’s see the network stats

We have two plugins in **volatility 2** (**connscan**) which makes pool scanner for tcp connections, and (**connections**) which Prints list of open connections

![A black background with white text](media/1b5e794430c0302f982f77a034c46277.png)**connscan plugin**

pid 1084 svchost.exe pid 1752 explorer.exe

![](media/3739b6df7cf3f5b21c5734c80278f06e.png)**connection plugin**

**Explanation:**

Since the malicious file has ben executed from the explorer, (**ppid of his ppid is explorer.exe**) , so we will focus on the explorer.exe connection, also because the other connections in connscan had belonged to svchost.exe, which is the main process of any running windows machine. Let’s also check what I’ve said using virustotal

![A blue screen with green text Description automatically generated](media/524720522ca0dcbab0534ef8e68a6677.png)Scanning the ip address (**65.54.81.89**) which belongs to (**svchost.exe**) process

![A screen shot of a computer Description automatically generated](media/20ba4386a03edd49285c1e8d925cd44b.png)Scanning the ip address (**207.46.21.123**) which belongs to (**svchost.exe**) process

Now, Scanning the ip address (**193.43.134.14**) which belongs to (**explorer.exe**) process

![A blue rectangular object with red text Description automatically generated](media/cc7e243763793c0d64ca7e8ed00045ee.png)

So, I’m right, the malicious ip address must be related to (**explorer.exe**) process

Also, it has suspicious files dropped related to that ip address (**193.43.134.14**)

![A screenshot of a computer Description automatically generated](media/5f1fe0dfd9c2708af22dd569739a6678.png)

![A screenshot of a computer Description automatically generated](media/f20645f3d83fdd32aa3569c248978e09.png)Let’s check the second one :

**![A screenshot of a computer Description automatically generated](media/12307981fa0368f8ae430bdf11ae7c9f.png)(Ydeku),** I think we’ve seen this before. Let’s go to Details section and get the names and Signature info :

From the first malicious process which its name was a valid MD5 hash (**b98679df6defbb3dc0e12463880c9dd7.exe**) has this scan :

![A screenshot of a computer Description automatically generated](media/dc7a4a2e2cbb49bafee05ec8349b3bd3.png)

![A screenshot of a computer Description automatically generated](media/df575c0204e1b2ed0969edca4bc2d006.png)And has these details:

**YARA Rules**

**Create rules based on all malicious files that we’ve got from the memory dump and from Zeus Banking Malware.**

First, Creating a custom rule based on all malicious files, all malicious file we need :

-   **invoice_2318362983713_823931342io.pdf.exe**
-   **b98679df6defbb3dc0e12463880c9dd7.exe**
-   **ihah.exe**
-   **vaelh.exe**
-   **anaxu.exe**

![A screen shot of a computer Description automatically generated](media/1f49945dac7ca6ff26d7f10cc1543559.png)

Generating the YARA rules using this command:

└─\$ sudo python3 yarGen.py -m /home/kali/Desktop/Proactive/ -o /home/kali/Desktop/YaraGen.yar

***

![A screenshot of a computer screen Description automatically generated](media/b0d2f37a3bfaf71647634097f0897e8b.png)

![A screen shot of a computer program Description automatically generated](media/de51295669d7acaa1dd834661c2a1403.png)Let’s read a sample of the YARA Rule that we generated:

Now let’s run the YARA rule on all malicious files inside (Malicious_Findings) Directory using this command:

1\. └─\$ yara YaraGen.yar Malicious_Findings

***

![A screen shot of a computer Description automatically generated](media/45fd1bf4bc251c1ef1d8a9b981a8d1e8.png)

Run YARA command to print matching strings (Here’s a sample of the whole output):

1\. └─\$ yara -s YaraGen.yar Malicious_Findings

***

![A screenshot of a computer program Description automatically generated](media/80e6f13bce12d010fe6c2a855d71f88c.png)
