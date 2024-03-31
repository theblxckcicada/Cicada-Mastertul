import argparse
import os
import sys
import subprocess
import socket
import re
from smbclient  import SambaClient,SambaClientError # Install using: pip install pysmb
import uuid

from smbprotocol.connection import Connection, Dialects


user_args = ""


def create_directories_if_not_exist(*directories):
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)



def create_files_if_not_exist(*files):
    for file_path in files:
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                file.write("")  # Write an empty string to the file







# script banner
def display_banner():
	print("""
	
	         ██████╗██╗ ██████╗ █████╗ ██████╗  █████╗                    
                ██╔════╝██║██╔════╝██╔══██╗██╔══██╗██╔══██╗                   
                ██║     ██║██║     ███████║██║  ██║███████║                   
                ██║     ██║██║     ██╔══██║██║  ██║██╔══██║                   
                ╚██████╗██║╚██████╗██║  ██║██████╔╝██║  ██║                   
                 ╚═════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   
                 |_ author _ 
			    | _ theblxckcicada _|                
                                                                              
███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ ████████╗██╗   ██╗██╗     
████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██║     
██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝   ██║   ██║   ██║██║     
██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗   ██║   ██║   ██║██
██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║   ██║   ╚██████╔╝███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
                                                                              
	""")
 
# argument management 
def get_args():
	    parser = argparse.ArgumentParser(description='Script description')
	    parser.add_argument('-u', '--username', help='Username for authentication')
	    parser.add_argument('-d', '--domain', help='Domain name of the target machine')
	    parser.add_argument('-p', '--password', help='Password for authentication')
	    parser.add_argument('-H', '--ntlm-hash', help='NTLM Hash for authentication')
	    parser.add_argument('-t', '--target', help='Target host or IP address')
	    parser.add_argument('-w', '--wordlist', default='rockyou.txt', help='Password list (default: rockyou.txt)')
	    parser.add_argument('--kerberos', action='store_true', help='Enable kerberoasting mode')
	    parser.add_argument('--ldap', action='store_true', help='Enable LDAP mode Enumeration')
	    parser.add_argument('--smb', action='store_true', help='Enable SMB mode Enumeration')
	    parser.add_argument('--full', action='store_true', help='Enable full mode Enumeration')
	    parser.add_argument('--winrm', action='store_true', help='Enable winrm mode Enumeration')
	    parser.add_argument('--bloodhound', action='store_true', help='Enable bloodhound mode Enumeration')
	    parser.add_argument('--crack', action='store_true', help='Crack Found Hashes')
	    args = parser.parse_args()
	    return args


# get arguments
user_args = get_args()
    
# Define directory paths
current_directory = os.getcwd()
base_directory = os.path.join(current_directory, "cicada_scan")
target_directory = os.path.join(base_directory, user_args.target)
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
cracked_kerberos_file = os.path.join(kerberos_directory, "NPUsers_cracked.txt")
lookupsid_file = os.path.join(lookupsid_directory, "lookupsid_file.txt")
users_file = os.path.join(lookupsid_directory, "users.txt")
smb_file = os.path.join(smb_directory, "share_drives.txt")
smb_shares_file = os.path.join(smb_directory, "share_names.txt")
host_file = "/etc/hosts"  # Assuming this is a system file, no creation needed



def setup_app():
    # Display banner
    display_banner()
    
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
        cracked_kerberos_file,
        lookupsid_file,
        users_file,
        smb_file,
        smb_shares_file
    )

def generate_cme_cmd(username,password,server,crack_type,cmd):
    message = f"sudo crackmapexec {crack_type} {server} -u '{username}' -p '{password}' {cmd}"
    return message

def run_command(message):
    try:
        command = subprocess.Popen(
                        message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = command.stdout.read() + command.stderr.read()
        return output.decode(encoding='cp1252')
    except Exception as error:
        return error
    
def list_smb_shares(username, password, server):
    command = generate_cme_cmd(username, password, server, "smb", "--shares")
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
        
        # save crackmap results to filel 
        save_to_file(smb_file,results)       
         
def save_to_file(destination,results):
    with open(destination,'w') as file:
            file.write(results)
            
def remove_empty_files(directory):
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
            os.remove(filepath)
            

if __name__ == "__main__":   
    setup_app()
    list_smb_shares('Administrator','Password1','mayorsec.local')
    remove_empty_files(current_directory)
