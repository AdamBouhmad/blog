+++
author = "Theme author"
categories = ["HIDS","Security", "Defense", "SIEM"]
date = "2018-04-20"
description = "HIDS Made Easy(pt1)"
featured = "wazuh-dash.png"
featuredalt = ""
featuredpath = ""
linktitle = ""
title = "HIDS Monitoring Made Easy"
type = "post"

+++

## Author's Note

This Blog, let alone this blog post, has been something I've been meaning to get off
the ground for quite some time. Because of this, I will attempt to curb my extreme 
enthusiasm as I attempt to write a meaningful post on one of my favorite technologies, HIDS. This is supposed to be a somewhat high-level look at a few different providers in the space. 

I hope you all enjoy the blog, and please, if you have questions or want me to talk/elaborate on a specific topic please send me a DM on twitter @adambouhmad. 

Thanks all, and enjoy!

## What is a HIDS

HIDS stands for Host-Based Intrustion Detection System. A HIDS is meant to monitor an individual host for possible malicious activity. Examples of malicious activity a HIDS could monitor and alert on could be anything from brute-force attempts on SSH to RCE like [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638). HIDS fall under the broad term that enterprise vendors now tend to call 'Endpoint Security'. 

The output of a successfully implemented incident response plan is the ability to tell a story. Your tools should be chosen carefully, setup, and configured properly to aid you in this goal of putting together the puzzle pieces from start to finish. Whereas previous Endpoint Security strategies focused heavily on signatures, now adays quite a bit more is important, as signatures don't always tell the tale. 

Here's a few examples of features that are necessary: 

- Querying of filesystem(Linux)
- FIM(File Integrity Monitoring)
- Some form of rootkit detection
- Log Monitoring/Analysis 

## Wazuh


Not to be confused with Seclist's Open Source Security mailing list(OS-SEC), [OSSEC is an open source host-based intrusion detection system](https://github.com/wazuh) aimed at helping you have visibility into actions happening on a machine. Unfortunately, I've sucummbed to my innate bias and have started off with one of my favorite HIDS, WAZUH. You may be scratching your forehead, as you begin to wonder why it's name that, or why you've never heard of Wazuh before. Well, Wazuh is actually a fork of the OSSEC project, focused specifically on maintaining some newer rulesets. It also provides support for AWS & PCI DSS controls. It performs log analysis, integrity checking, rootkit detection, time-based alerting, and active response. Additionally, the Wazuh project provides support for ingestion and alerting on AWS Cloudtrail events and events and improved alerts PCI-DSS compliance.

Wazuh can stand alone, however it's best to be able to view and query information about alerts retrospectively, event processing, total agents connected, and so forth. This is where you may choose to pipe info to Elasticsearch, or forward to Splunk. 

Aide from Wazuh being a HIDS, it can also function as a SIM/SIEM as it performs log aggregation, analysis, integrity checking, rootkit detection, time-based alerting, and active response. Combine all of this functionality with the ability to index these events elsewhere for longer-term storage to meet retrospective needs, as well as a nice UI, and voila, you have yourself a fully-functioning Open Source SIEM. 

![Wazuh Dash](/img/main/wazuh.jpg)

## Architecture

There are multiple deployment strategies for Wazuh. 

 * **Local** 

	- This is a single agent install with no managing server to forward local events to. All rules are located on the host machine, which means that they too must be updated on the host machine. 

* **Agent**
	- The agent gathers information and forwards these events onward to a defined Wazuh Server for analysis and correlation. 

* **Hybrid**
	- A Wazuh server is setup to manage multiple agents, while having an agent of it's own that forwards it's logs to another Wazuh server. Installs the server in /var/ossec, as well as the Server's agent in /var/ossec/agent. 

* **Server**
	- Central part of a wazuh deployment. Wazuh stores file integrity checking databases, logs, events, and system audit entries. Rules, decorders, and major config options are stored here, allowing you to modify them at will. 

Typically you will have a Wazuh Server(or cluster) with multiple agents forwarding events to the server(s).

**To check how many wazuh agents your server _can_ support by default, you can run /var/ossec/bin/agent_control -m on the Wazuh Server. Note that your defined max agent limit should not exceed your ulimit**

Regardless of the deployment strategy that you choose for your environment, the event to alert flow will look like this: 

<p align="center">
<img src="/img/main/event_flow.jpg" alt="IMAGE ALT TEXT HERE" width="450" height="700" border="10"/></a></p>


## Rule Classification

Alerts in Wazuh are on a scale of 0-15. Here is how they're defined:

**Level 0:** Ignored, no action taken Primarily used to avoid false positives. These rules are scanned before all the others and include events with no
security relevance.

**Level 1:** Not in use by OSSEC currently

**Level 2:** System low priority notification System notification or status messages that have no security relevance.

**Level 3:** Successful/authorized events Successful login attempts, firewall allow events, etc.

**Level 4:** System low priority errors Errors related to bad configurations or unused devices/applications. They have no security relevance and are usually caused by default installations or software testing.

**Level 5:** User-generated errors Missed passwords, denied actions, etc. These messages typically have no security relevance.

**Level 6:** Low relevance attacks Indicate a worm or a virus that provide no threat to the system such as a Windows worm attacking a Linux server. They also include frequently triggered IDS events and common error events.

**Level 7:** “Bad word” matching. They include words like “bad”, “error”, etc

**Level 8:** First time seen - Include first time seen events. First time an IDS event is fired or the first time an user logged in. If you just started using OSSEC HIDS these messages will probably be frequently. After a while they should go away, It also includes security relevant actions (like the starting of a sniffer or something like that).

**Level 9:** Error from invalid source Include attempts to login as an unknown user or from an invalid source. The message might have security relevance especially if repeated. They also include errors regarding the admin or root account.

**Level 10:** Multiple user generated errors Include multiple bad passwords, multiple failed logins, etc. They might indicate an attack, or it might be just that a user forgot his or her credentials.

**Level 11:** Integrity checking warning - They include messages regarding the modification of binaries or the presence of rootkits (by rootcheck). If you just modified your system configuration you should be fine regarding the “syscheck” messages. They may indicate a successful attack. Also included IDS events that will be ignored (high number of repetitions).

**Level 12:** High-importance event Include error or warning messages from the system, kernel, etc. They might indicate an attack against a specific application.

**Level 13:** Unusual error (high importance) Common attack patterns such as a buffer overflow attempt, a larger than normal syslog message, or a larger than normal URL string.

**Level 14:** High importance security event. Typically the result of the correlation of multiple attack rules and indicative of an attack.

**Level 15:** Attack successful. Very small chance of false positive. Immediate attention is necessary.

Let's take a look at a few example alerts

Let's say a user attempts to ssh into a machine, but the user specifies an incorrect username. Here is an example alert that would be generated and found in the alerts.log file. 

```
** Alert 1489690871.11591: -
syslog,sshd,invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10. 2.5,pci_dss_10.6.1,
2017 Mar 16 19:01:11 ip-192-168-10-1->/var/log/auth.log
Rule: 5710 (level 5) -> 'sshd: Attempt to login using a non-existent user' Src IP: 192.168.1.4
Mar 16 19:01:11 ip-192-168-10-1 sshd[26611]: Invalid user bouhmad from 192.168.1.4
```

In this alert, there are a few important points. The source ip of the offender in this case is 192.168.1.4, and the destination is 192.168.10.1. The event is classified as hitting the Level 5 threshold(more specifically rule 5710), in which this usually means a user inputted an incorrect password, or specified a non existent user. We can also see the pci controls this rule is aiding(more on that later), and the group this alert is apart of, sshd in this case. 


## Decoders
OSSEC uses decoders to parse log files that are put under monitoring. Once the appropriate decoder is found for a log, it will parse out fields defined in /var/ossec/wazuh/etc/decoders/, and then compare those values to values in the rule files defined at /var/ossec/wazuh/etc/rules/. If the
values match a specific rule, an alert will be triggered and sent to the alerts.log file.
There are two types of decoding events, predecoding and decoding. Pre-decoding extracts static information from well known fields in a given event. For instance, in syslog, a field that may get data extracted from could be hostname, log, time, date, etc...

```
Mar 16 18:54:44 ip-192-168-10-2 audispd: node=ip-192-168-254-9
type=CRED_ACQ msg=audit(1489690484.495:6098): pid=26144 uid=0
auid=4294967295 ses=4294967295 msg='op=PAM:setcred acct="bouhmad"
exe="/usr/sbin/sshd" hostname=ip-192-168-10-1.ec2.internal
addr=192.168.10.1 terminal=ssh res=success'
```

In this case, the pre-decoder would extract out the fields such as hostname, address, acct, and so forth.

Decoding, on the other hand, extracts out non-static information that may fit those fields that were received from the pre-decoding phase. This could be actual ip addresses, usernames, and so forth. This non-static info from specific events will be used to check for correlation between
other rules later on.


>**If Active Response is enabled, Wazuh turns into a HIPS and will block specific alerts that you pass to it: http://ossec-docs.readthedocs.io/en/latest/manual/ar/ar-unix.html#commands-configuration**


```
** Alert 1489690485.8235: -
syslog,sshd,authentication_success,pci_dss_10.2.5,
2017 Mar 16 18:54:45 ip-192-168-10-2->/var/log/auth.log
Rule: 5715 (level 3) -> 'sshd: authentication success.'
Src IP: 192.168.10.1
User: ubuntu
Mar 16 18:54:44 ip-192-168-254-9 sshd[26144]: Accepted publickey for ubuntu from 192.168.10.2 port 59884 ssh2: RSA d2:09:c3:b4:04:d3:2f:df:43:8c:12:fc:66:db:10:a3
```

## Logging
Events are automatically sent to the Wazuh Manager. What events your agents send all depends on the agent.conf configuration that's pushed down to them from the server. This can be defined in
/var/ossec/etc/shared/agent.conf.

>**Agent configuration will be propagated generally within 30 minutes to all hosts. To speed this process up and make the Wazuh Server aware of a change, you can do the following: service wazuh-manager restart && /var/ossec/bin/agent-control -R -a**


Alerts on the OSSEC Server are stored in /var/ossec/logs/alerts/alerts.json. All events, however, are stored in /var/ossec/logs/archives/archives.json. You should pipe these events to your event management solution(e.g splunk or elasticsearch). 


## Alerting
After an alert is generated based upon an event, OSSEC makes the decision of where to pipe this message to (email or sms, for example). Refer to the Diagram in the Architecture section in this blog post. 

>**Good read regarding alerting: http://www.ossec.net/ossec-docs/OSSEC-book-ch4.pdf "Notes from the Underground"**


## Rule Files
After events have been through the pre-decoder and decoder, the events are either correlated with the current ruleset on the OSSEC Server (agent install), or they are just done locally (local install). OSSEC rules are stored in /var/ossec/rules. The rules are in XML format. Here are a
listing of the current rulesets for Wazuh: https://www.wazuh.com/resources/OSSEC_Ruleset.pdf

An important thing to note is that we can specify whether a rule is composite or atomic.
_Atomic rules_ are based on single events without any correlation to other events that may have taken place. An atomic rule could just be alerting everytime a user that isnt named 'adam' does a netstat. 

_Composite rules_, on the other hand, are based on multiple events. So whereas before we weren't alerting if the user adam did a netstat, we can now have a custom rule that says if 'adam' or 'bouhmad' do a netstat after 7PM, and try to modify a binary in /usr/bin, send an alert because potentially something malicious may be going on.

Let's walk through an example rule: 

>**OSSEC uses Rule ID's to identify different rulesets. User defined rules range from 100,000–119,999 inclusive.**


*Original Rule*
```
<rule id=“5712” level=“10” frequency=“6” timeframe=“120” ignore=“60”>
 <if_matched_sid>5710</if_matched_sid>
 <description>SSHD brute force trying to get access to the
system.</description>
 <group>authentication_failures,</group>
</rule>
```

This rule is defined as Level 10: Multiple user generated errors Include multiple bad passwords, multiple failed logins, etc. The current timeframe to alert on a bruteforce attempt is six events within 120 seconds create an alarm. The SID (Security Identifier), is the rule number that identifies this rule. The description as well as the group are required. The description allows you to differentiate between rules as you create them, and thus is ouputted to the user when theyre notified of a specific event. The group is also required, and will allow you to further identify where a specific rule falls into place. In this case, ssh brute force falls into authentication failures that is of the group type Authentication Control. 

Rule frequency is also something that can be tuned in the event of alerts being spammed. A user would have to find(grep is your best friend) & copy over the ruleset from /var/ossec/rules/ to /var/ossec/rules/local_rules.xml, modify the rule's frequency there, and set the rule to be overwritten. This is considered best practice, as the local_rules.xml file will not be overwritten when you update Wazuh. Here is an example of the above ruleset being added and modified in the local_rules xml file:

*Modified Rule*
```
# vi /var/ossec/rules/local_rules.xml
<rule id=“5712” level=“10” frequency=“15” timeframe=“120” ignore=“60”
overwrite=“yes”>
 <if_matched_sid>5710</if_matched_sid>
 <description>SSHD brute force trying to get access to the system.</description>
 <group>authentication_failures,</group>
</rule>
```

Since OSSEC HIDS has over 600 default rules and you will more than likely be processing a large volume of events, it's in your best interest to understand your environment and ignore rules that may not apply to your environment (e.g cisco ios rules in a juniper shop). 

Having all of these rules may increase overhead as an OSSEC server attempts to correlate decoded events with the rules to then alert on. For this reason, we will want to add these rules to local_rules.xml by specifying their rule_ids, and then setting them to the rule classification level 0. This means that those rules will be ignored.

```
# vi /var/ossec/rules/local_rules.xml
 <rule id="100005" level="0">
 <if_sid>591</if_sid>
 <description> Unneeded rule ____ </description>
</rule>
```

## Integrity Checking

By default, the integrity checking daemon, known as Syscheck, periodically runs every six hours. Syscheck _checks_ if specific items on the filesystem have been changed over the course of time by comparing them to a previously taken checksum. If changes have been made, an alert is sent out. To prevent CPU usage from spiking, the scans are performed slowly. 

>**Never modify rules directly in the /var/ossec/rules directory. Any changes will be overwritten during OSSEC updates, and deletion of rules can cause issues with OSSEC. Ensure that changes are made in /var/ossec/rules/local_rules.xml.**


Syscheck is invaluable, as it will allow you to detect malicious files ending up in obscure areas(e.g /tmp/ or /dev/) 

For more information on various configuration options, visit here: http://ossec-docs.readthedocs.io/en/latest/manual/syscheck/

## Advanced Options
Whereas the main configuration file for OSSEC is found at /var/ossec/etc/ossec.conf, the advanced configuration file is found at /var/ossec/etc/internal_options.conf. This file stores runtime configurations for OSSEC, and should rarely ever be touched. This config file is generally modified to enable advanced debugging, or to change the cadence of different services such as syscheck. 


##Alerts from AWS CloudTrail
Alerting on cloudtrail events may not seem extremely important, but it could be an indicator of potential malicious activity. In this case, think about a security group being modified to 0.0.0.0/0 on a public facing resource, or  
Cloudtrail alerting is made possibly by a fairly simple script called getawslog.py published by the Wazuh project. This script pulls the CloudTrail log data from your configured S3 buckets and formats it to be decoded by OSSEC. When paired with the Amazon rules also published by Wazuh, you'll be able to alert on actions occuring in your AWS accounts. 


## PCI DSS
♫♬♪ _Because you love compliance_ ♬♪

Aside from playing the violin when I was in middle school, I'm musically inept. How does that last piece fit into this whole post... I'm not sure. But hey, you've made it this far and are now, for better or for worse, wondering about compliance and how Wazuh fits into this piece. Or maybe you're not wondering ---- I'm not sure. But hey, Wazuh PCI control information can be found here: https://documentation.wazuh.com/2.0/pci-dss/index.html


## Questions

Have any questions? Shoot me message at @adambouhmad on twitter and I'll be more than happy to help -- Thanks for reading! 
