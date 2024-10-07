# Cicada-Mastertul
## Description 
The tool allows users to authenticate with a target domain using either usernames and passwords or NTLM hashes, and it provides a wide range of enumeration options to gather information about domain users, services, and vulnerabilities. It can also assist with cracking password hashes and extracting sensitive information for further exploitation.

## Installation and Setup 
To set up Impacket and use the tool, you'll need to run the following command. Note: If you have set up your Kali using Dewalt's pimpmykali (https://github.com/Dewalt-arch/pimpmykali), you don't need to run the setup script.

```markdown
sudo python3 cicada-mastertul.py --setup
 ```
 
![image](https://github.com/user-attachments/assets/e703cf85-bf49-4fbd-be40-ba9dedbe30d2)


https://github.com/theblxckcicada/Cicada-Mastertul/assets/68484817/77d0adb5-2223-4ae9-b93a-3d15b4bc8eaa


```markdown
## Help Menu
usage: cicada-mastertul.py [-h] [-u USERNAME] [-d DOMAIN] [-p PASSWORD] [-H NTLM_HASH] [-t TARGET] [-w WORDLIST]
                      [-us USERSFILE] [--kerberos] [--lookupsid] [--npusers] [--userspn] [--ldap]
                      [--smb] [--full] [--winrm] [--bloodhound] [--crack]

Script description

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for authentication
  -d DOMAIN, --domain DOMAIN
                        Domain name of the target machine
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -H NTLM_HASH, --ntlm-hash NTLM_HASH
                        NTLM Hash for authentication
  -t TARGET, --target TARGET
                        Target host or IP address
  -w WORDLIST, --wordlist WORDLIST
                        Password list (default: rockyou.txt)
  --setup               Fix Impacket scripts
  -us USERSFILE, --usersfile USERSFILE
                        List of domain users
  --kerberos            Enable kerberoasting mode
  --lookupsid           Enable lookupsid mode
  --npusers             Enable GetNPUsers mode
  --userspn             Enable GetUserSPNs mode
  --ldap                Enable LDAP mode Enumeration
  --smb                 Enable SMB mode Enumeration
  --full                Enable full mode Enumeration
  --winrm               Enable winrm mode Enumeration
  --bloodhound          Enable bloodhound mode Enumeration
  --crack               Crack Found Hashes
```
