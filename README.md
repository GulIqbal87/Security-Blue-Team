# Security-Blue-Team
Cybersecurity Blue Team Collections
A collection of resources, tools, and other things for blue teams.


Cybersecurity blue teams are groups of individuals who identify security flaws in information technology systems, verify the effectiveness of security measures, and monitor the systems to ensure that implemented defensive measures remain effective in the future. While not exclusive, this list is heavily biased towards Free Software projects and against proprietary products or corporate services. For offensive TTPs, please see awesome-pentest.
Contents
Automation
Communications security (COMSEC)
DevSecOps
Fuzzing
Honeypots
Host-based tools
Incident Response tools
IR management consoles
Evidence collection
Threat hunting
Network Security Monitoring (NSM)
Network perimeter defenses
Firewall appliances or distributions
Operating System distributions
Preparedness training and wargaming
Security Information and Event Management (SIEM)
Service and performance monitoring
Threat intelligence
Tor Onion service defenses
Transport-layer defenses
macOS-based defenses
Windows-based defenses
Automation
Autosnort - Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions.
Posh-VirusTotal - PowerShell interface to VirusTotal.com APIs.
python-dshield - Pythonic interface to the Internet Storm Center/DShield API.
python-sandboxapi - Minimal, consistent Python API for building integrations with malware sandboxes.
python-stix2 - Python APIs for serializing and de-serializing Structured Threat Information eXpression (STIX) JSON content, plus higher-level APIs for common tasks.
Communications security (COMSEC)
GPG Sync - Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team.
DevSecOps
See also awesome-devsecops.

BlackBox - Safely store secrets in Git/Mercurial/Subversion by encrypting them "at rest" using GnuPG.
Clair - Static analysis tool to probe for vulnerabilities introduced via application container (e.g., Docker) images.
Gauntlt - Pentest applications during routine continuous integration build pipelines.
Git Secrets - Prevents you from committing passwords and other sensitive information to a git repository.
Prowler - Tool based on AWS-CLI commands for Amazon Web Services account security assessment and hardening.
Vault - Tool for securely accessing secrets such as API keys, passwords, or certificates through a unified interface.
git-crypt - Transparent file encryption in git; files which you choose to protect are encrypted when committed, and decrypted when checked out.
SonarQube - Continuous inspection tool that provides detailed reports during automated testing and alerts on newly introduced security vulnerabilities.
Fuzzing
See Awesome-Fuzzing.

Honeypots
See also awesome-honeypots.

CanaryTokens - Self-hostable honeytoken generator and reporting dashboard; demo version available at CanaryTokens.org.
Host-based tools
Artillery - Combination honeypot, filesystem monitor, and alerting system designed to protect Linux and Windows operating systems.
Fail2ban - Intrusion prevention software framework that protects computer servers from brute-force attacks.
Open Source HIDS SECurity (OSSEC) - Fully open source and free, feature-rich, Host-based Instrusion Detection System (HIDS).
Rootkit Hunter (rkhunter) - POSIX-compliant Bash script that scans a host for various signs of malware.
Incident Response tools
See also awesome-incident-response.

aws_ir - Automates your incident response with zero security preparedness assumptions.
IR management consoles
CIRTKit - Scriptable Digital Forensics and Incident Response (DFIR) toolkit built on Viper.
Fast Incident Response (FIR) - Cybersecurity incident management platform allowing for easy creation, tracking, and reporting of cybersecurity incidents.
TheHive - Scalable, free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs, featuring tight integration with MISP.
threat_note - Web application built by Defense Point Security to allow security researchers the ability to add and retrieve indicators related to their research.
Evidence collection
OSXAuditor - Free macOS computer forensics tool.
OSXCollector - Forensic evidence collection & analysis toolkit for macOS.
ir-rescue - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
Margarita Shotgun - Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition.
Threat hunting
(Also known as hunt teaming and threat detection.)

See also awesome-threat-detection.

CimSweep - Suite of CIM/WMI-based tools enabling remote incident response and hunting operations across all versions of Windows.
DeepBlueCLI - PowerShell module for hunt teaming via Windows Event logs.
GRR Rapid Response - Incident response framework focused on remote live forensics consisting of a Python agent installed on assets and Python-based server infrastructure enabling analysts to quickly triage attacks and perform analysis remotely.
Hunting ELK (HELK) - All-in-one Free Software threat hunting stack based on Elasticsearch, Logstash, Kafka, and Kibana with various built-in integrations for analytics including Jupyter Notebook.
Mozilla InvestiGator (MIG) - Platform to perform investigative surgery on remote endpoints.
PSHunt - PowerShell module designed to scan remote endpoints for indicators of compromise or survey them for more comprehensive information related to state of those systems.
PSRecon - PSHunt-like tool for analyzing remote Windows systems that also produces a self-contained HTML report of its findings.
PowerForensics - All in one PowerShell-based platform to perform live hard disk forensic analysis.
Redline - Freeware endpoint auditing and analysis tool that provides host-based investigative capabilities, offered by FireEye, Inc.
Scout2 - Security tool that lets Amazon Web Services administrators assess their environment's security posture.
Network Security Monitoring (NSM)
Bro - Powerful network analysis framework focused on security monitoring.
ChopShop - Framework to aid analysts in the creation and execution of pynids-based decoders and detectors of APT tradecraft.
Maltrail - Malicious network traffic detection system.
Respounder - Detects the presence of the Responder LLMNR/NBT-NS/MDNS poisoner on a network.
Security Monkey - Monitors your AWS and GCP accounts for policy changes and alerts on insecure configurations.
Snort - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
SpoofSpotter - Catch spoofed NetBIOS Name Service (NBNS) responses and alert to an email or log file.
Suricata - Free, cross-platform, IDS/IPS with on- and off-line analysis modes and deep packet inspection capabilities that is also scriptable with Lua.
Wireshark - Free and open-source packet analyzer useful for network troubleshooting or forensic netflow analysis.
netsniff-ng - Free and fast GNU/Linux networking toolkit with numerous utilities such as a connection tracking tool (flowtop), traffic generator (trafgen), and autonomous system (AS) trace route utility (astraceroute).
Network perimeter defenses
fwknop - Protects ports via Single Packet Authorization in your firewall.
ssh-audit - Simple tool that makes quick recommendations for improving an SSH server's security posture.
Firewall appliances or distributions
OPNsense - FreeBSD based firewall and routing platform.
pfSense - Firewall and router FreeBSD distribution.
Operating System distributions
Computer Aided Investigative Environment (CAINE) - Italian GNU/Linux live distribution that pre-packages numerous digital forensics and evidence collection tools.
Security Onion - Free and open source GNU/Linux distribution for intrusion detection, enterprise security monitoring, and log management.
Preparedness training and wargaming
(Also known as adversary emulation, threat simulation, or similar.)

APTSimulator - Toolset to make a system look as if it was the victim of an APT attack.
Atomic Red Team - Library of simple, automatable tests to execute for testing security controls.
DumpsterFire - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events for Blue Team drills and sensor/alert mapping.
Metta - Automated information security preparedness tool to do adversarial simulation.
Network Flight Simulator (flightsim) - Utility to generate malicious network traffic and help security teams evaluate security controls and audit their network visibility.
RedHunt OS - Ubuntu-based Open Virtual Appliance (.ova) preconfigured with several threat emulation tools as well as a defender's toolkit.
Security Information and Event Management (SIEM)
AlienVault OSSIM - Single-server open source SIEM platform featuring asset discovery, asset inventorying, behavioral monitoring, and event correlation, driven by AlienVault Open Threat Exchange (OTX).
Prelude SIEM OSS - Open source, agentless SIEM with a long history and several commercial variants featuring security event collection, normalization, and alerting from arbitrary log input and numerous popular monitoring tools.
Service and performance monitoring
See also awesome-sysadmin#monitoring.

Icinga - Modular redesign of Nagios with pluggable user interfaces and an expanded set of data connectors, collectors, and reporting tools.
Nagios - Popular network and service monitoring solution and reporting platform.
OpenNMS - Free and feature-rich networking monitoring system supporting multiple configurations, a variety of alerting mechanisms (email, XMPP, SMS), and numerous data collection methods (SNMP, HTTP, JDBC, etc).
osquery - Operating system instrumentation framework for macOS, Windows, and Linux, exposing the OS as a high-performance relational database that can be queried with a SQL-like syntax.
Threat intelligence
See also awesome-threat-intelligence.

Active Directory Control Paths - Visualize and graph Active Directory permission configs ("control relations") to audit questions such as "Who can read the CEO's email?" and similar.
DATA - Credential phish analysis and automation tool that can acccept suspected phishing URLs directly or trigger on observed network traffic containing such a URL.
Forager - Multi-threaded threat intelligence gathering built with Python3 featuring simple text-based configuration and data storage for ease of use and data portability.
GRASSMARLIN - Provides IP network situational awareness of industrial control systems (ICS) and Supervisory Control and Data Acquisition (SCADA) by passively mapping, accounting for, and reporting on your ICS/SCADA network topology and endpoints.
MLSec Combine - Gather and combine multiple threat intelligence feed sources into one customizable, standardized CSV-based format.
Malware Information Sharing Platform and Threat Sharing (MISP) - Open source software solution for collecting, storing, distributing and sharing cyber security indicators.
ThreatIngestor - Extendable tool to extract and aggregate IOCs from threat feeds including Twitter, RSS feeds, or other sources.
Unfetter - Identifies defensive gaps in security posture by leveraging Mitre's ATT&CK framework.
Viper - Binary analysis and management framework enabling easy organization of malware and exploit samples.
Tor Onion service defenses
See also awesome-tor.

OnionBalance - Provides load-balancing while also making Onion services more resilient and reliable by eliminating single points-of-failure.
Vanguards - Version 3 Onion service guard discovery attack mitigation script (intended for eventual inclusion in Tor core).
Transport-layer defenses
Certbot - Free tool to automate the issuance and renewal of TLS certificates from the LetsEncrypt Root CA with plugins that configure various Web and e-mail server software.
OpenVPN - Open source, SSL/TLS-based virtual private network (VPN).
Tor - Censorship circumvention and anonymizing overlay network providing distributed, cryptographically verified name services (.onion domains) to enhance publisher privacy and service availability.
macOS-based defenses
macOS Fortress - Automated configuration of kernel-level, OS-level, and client-level security features including privatizing proxying and anti-virus scanning for macOS.
Stronghold - Easily configure macOS security settings from the terminal.
Windows-based defenses
See also awesome-windows#security and awesome-windows-domain-hardening.

HardenTools - Utility that disables a number of risky Windows features.
NotRuler - Detect both client-side rules and VBScript enabled forms used by the Ruler attack tool when attempting to compromise a Microsoft Exchange server.
Sigcheck - Audit a Windows host's root certificate store against Microsoft's Certificate Trust List (CTL).
Sticky Keys Slayer - Establishes a Windows RDP session from a list of hostnames and scans for accessibility tools backdoors, alerting if one is discovered.
Windows Secure Host Baseline - Group Policy objects, compliance checks, and configuration tools that provide an automated and flexible approach for securely deploying and maintaining the latest releases of Windows 10.
WMI Monitor - Log newly created WMI consumers and processes to the Windows Application event log.
