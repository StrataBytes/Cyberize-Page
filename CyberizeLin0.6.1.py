import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os
import sys

def is_root():
    return os.geteuid() == 0

if not is_root():
    print("This script needs to be run with elevated privileges. Restarting with sudo...")
    subprocess.run(['sudo', 'python3'] + sys.argv)
    sys.exit()

def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        messagebox.showinfo("Success", result)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error executing '{command}': {str(e.output)}")

def list_users():
    run_command("getent passwd")

def update_system():
    run_command("sudo apt-get update && sudo apt-get upgrade -y && sudo apt autoremove -y")

def configure_firewall():
    run_command("sudo ufw enable && sudo ufw default deny")

def list_open_ports():
    run_command("sudo lsof -i -P -n | grep LISTEN")

def list_running_services():
    run_command("service --status-all")

def disable_guest_account():
    messagebox.showinfo("Info", "Guest account is disabled by default on Ubuntu 20.04 and later.")

def install_antivirus():
    run_command("sudo apt-get install clamav clamav-daemon -y && sudo freshclam && sudo systemctl start clamav-daemon && sudo systemctl enable clamav-daemon")

def check_unnecessary_packages():
    run_command("apt list --installed")

def remove_unnecessary_packages():
    messagebox.showinfo("Info", "You should manually check and remove unnecessary packages.")

def list_scheduled_tasks():
    run_command("crontab -l && sudo ls /etc/cron.*")

def check_firewall_status():
    run_command("sudo ufw status")

def list_user_groups():
    run_command("compgen -g")

def list_system_info():
    run_command("lsb_release -a && uname -a")

def perform_security_audit():
    run_command("sudo lynis audit system")

def monitor_logs():
    messagebox.showinfo("Info", "You need to configure and use a log monitoring tool like Logwatch.")

def backup_system():
    messagebox.showinfo("Info", "You need to set up and configure a backup tool like Rsnapshot.")

def manage_user_accounts():
    messagebox.showinfo("Info", "You need to manually manage user accounts using 'useradd', 'usermod', and 'userdel' commands.")

def monitor_network():
    messagebox.showinfo("Info", "You need to use a network monitoring tool like nload or iftop.")

def securely_delete_files():
    messagebox.showinfo("Info", "You can use the 'shred' command to securely delete files.")

def enforce_password_policies():
    run_command("sudo apt-get install libpam-pwquality -y && sudo nano /etc/security/pwquality.conf")

def check_disk_space():
    run_command("df -h")

def check_for_rootkits():
    run_command("sudo apt-get install rkhunter -y && sudo rkhunter --update && sudo rkhunter --check")

def secure_ssh_config():
    run_command("sudo nano /etc/ssh/sshd_config")

def manage_services():
    messagebox.showinfo("Info", "You can manage services using 'systemctl' or 'service' commands.")

def configure_secure_boot():
    messagebox.showinfo("Info", "Secure Boot can be configured in your system's BIOS settings.")

def show_hardware_info():
    run_command("sudo lshw")

def manage_ssh_keys():
    messagebox.showinfo("Info", "You can manage SSH keys using 'ssh-keygen', 'ssh-add', and updating the '~/.ssh/authorized_keys' file.")

def check_file_permissions():
    messagebox.showinfo("Info", "You need to manually check and set file permissions using 'chmod' and 'chown' commands.")

def monitor_system_resources():
    run_command("top")

def show_software_inventory():
    run_command("dpkg-query -l")

def file_search():
    file_type = simpledialog.askstring("Input", "Enter the type of file to search for:")
    if file_type:
        command = f"sudo find /home -type f -name '*.{file_type}'"
        run_command(command)

def create_gui():
    root = tk.Tk()
    root.geometry("700x500")
    root.title("Cyberize Linux 0.6 | @Huckleboard (git) | Ubuntu kit")

    tree = ttk.Treeview(root)

    categories = {
        "User & System Info": ["List Users", "List System Info", "List User Groups", "Show Hardware Info", "File Search"],
        "Security Settings": ["Update System", "Configure Firewall", "Check Firewall Status", "List Open Ports", "List Running Services", "Disable Guest Account", "Install Antivirus", "Check Unnecessary Packages", "Remove Unnecessary Packages", "List Scheduled Tasks", "Secure SSH Configuration", "Check for Rootkits", "Enforce Password Policies", "Manage User Accounts", "Backup System", "Monitor Network", "Monitor Logs", "Securely Delete Files", "Manage Services", "Configure Secure Boot", "Check Disk Space", "Perform Security Audit", "Manage SSH Keys", "Check File Permissions", "Monitor System Resources", "Show Software Inventory"],
    }

    tools = {
        "List Users": list_users,
        "Update System": update_system,
        "Configure Firewall": configure_firewall,
        "List Open Ports": list_open_ports,
        "List Running Services": list_running_services,
        "Disable Guest Account": disable_guest_account,
        "Install Antivirus": install_antivirus,
        "Check Unnecessary Packages": check_unnecessary_packages,
        "Remove Unnecessary Packages": remove_unnecessary_packages,
        "List Scheduled Tasks": list_scheduled_tasks,
        "Check Firewall Status": check_firewall_status,
        "List User Groups": list_user_groups,
        "List System Info": list_system_info,
        "Perform Security Audit": perform_security_audit,
        "Monitor Logs": monitor_logs,
        "Backup System": backup_system,
        "Manage User Accounts": manage_user_accounts,
        "Monitor Network": monitor_network,
        "Securely Delete Files": securely_delete_files,
        "Enforce Password Policies": enforce_password_policies,
        "Check Disk Space": check_disk_space,
        "Check for Rootkits": check_for_rootkits,
        "Secure SSH Configuration": secure_ssh_config,
        "Manage Services": manage_services,
        "Configure Secure Boot": configure_secure_boot,
        "Show Hardware Info": show_hardware_info,
        "Manage SSH Keys": manage_ssh_keys,
        "Check File Permissions": check_file_permissions,
        "Monitor System Resources": monitor_system_resources,
        "Show Software Inventory": show_software_inventory,
        "File Search": file_search,
    }

    for category, tools_list in categories.items():
        parent = tree.insert("", "end", text=category)
        for tool in tools_list:
            tree.insert(parent, "end", text=tool)
    
    tree.pack(fill="both", expand=True)
    tree.bind("<Double-Button-1>", lambda event, tree=tree, tools=tools: execute_selected_tool(event, tree, tools))

    root.mainloop()

def execute_selected_tool(event, tree, tools):
    selected_item = tree.focus()
    if selected_item:
        selected_tool = tree.item(selected_item)["text"]
        if selected_tool in tools:
            tools[selected_tool]()

if __name__ == "__main__":
    create_gui()
