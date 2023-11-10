import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os
import sys
#import psutil 

def is_root():
    return os.geteuid() == 0

if not is_root():
    print("This script needs to be run with elevated privileges. Restarting with sudo...")
    subprocess.run(['sudo', 'python3'] + sys.argv)
    sys.exit()
def run_command(command, display_output=False, output_widget=None):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout if result.stdout else result.stderr
        if display_output and output_widget:
            # Inserting the output to the text widget
            output_widget.insert(tk.END, f"{command} output:\n{output}\n")
            output_widget.see(tk.END)  # Auto-scroll to the end
        messagebox.showinfo("Success", f"'{command}' executed successfully.")
    except subprocess.CalledProcessError as e:
        if output_widget:
            output_widget.insert(tk.END, f"Error executing '{command}': {e.output}\n")
            output_widget.see(tk.END)
        messagebox.showerror("Error", f"Error executing '{command}': {str(e)}")

def list_users(output_widget=None):
    run_command("getent passwd", True)

def clean_old_kernels():
    run_command("sudo apt-get autoremove --purge", True)

def remove_orphaned_packages():
    run_command("sudo deborphan | xargs sudo apt-get -y remove --purge", True)

def clear_cache():
    run_command("sudo apt-get clean", True)

def system_resource_monitor(output_widget):
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    output_widget.insert(tk.END, f"CPU Usage: {cpu_usage}%\nMemory Usage: {memory_usage}%\nDisk Usage: {disk_usage}%\n")
    output_widget.see(tk.END)

def show_detailed_system_info(output_widget):
    run_command("hostnamectl", True, output_widget)

def update_system():
    run_command("sudo apt-get update && sudo apt-get upgrade -y && sudo apt autoremove -y")

def configure_firewall():
    run_command("sudo ufw enable && sudo ufw default deny")

def list_open_ports():
    run_command("sudo lsof -i -P -n | grep LISTEN", True)

def list_running_services():
    run_command("service --status-all", True)

def disable_guest_account():
    messagebox.showinfo("Info", "Guest account is disabled by default on Ubuntu 20.04 and later.")

def install_antivirus():
    run_command("sudo apt-get install clamav clamav-daemon -y && sudo freshclam && sudo systemctl start clamav-daemon && sudo systemctl enable clamav-daemon")

def check_unnecessary_packages():
    run_command("apt list --installed", True)

def remove_unnecessary_packages():
    messagebox.showinfo("Info", "You should manually check and remove unnecessary packages.")

def list_scheduled_tasks():
    run_command("crontab -l && sudo ls /etc/cron.*", True)

def check_firewall_status():
    run_command("sudo ufw status", True)

def list_user_groups():
    run_command("compgen -g", True)

def list_system_info():
    run_command("lsb_release -a && uname -a", True)

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
    run_command("df -h", True)

def check_for_rootkits():
    run_command("sudo apt-get install rkhunter -y && sudo rkhunter --update && sudo rkhunter --check")

def secure_ssh_config():
    run_command("sudo nano /etc/ssh/sshd_config")

def manage_services():
    messagebox.showinfo("Info", "You can manage services using 'systemctl' or 'service' commands.")

def configure_secure_boot():
    messagebox.showinfo("Info", "Secure Boot can be configured in your system's BIOS settings.")

def show_hardware_info():
    run_command("sudo lshw", True)

def manage_ssh_keys():
    messagebox.showinfo("Info", "You can manage SSH keys using 'ssh-keygen', 'ssh-add', and updating the '~/.ssh/authorized_keys' file.")

def check_file_permissions():
    messagebox.showinfo("Info", "You need to manually check and set file permissions using 'chmod' and 'chown' commands.")

def monitor_system_resources():
    run_command("top")

def show_software_inventory():
    run_command("dpkg-query -l", True)

def file_search():
    file_type = simpledialog.askstring("Input", "Enter the file type to search for:")
    if file_type:
        run_command(f"sudo find /home -type f -name '*.{file_type}'", True)
    else:
        messagebox.showerror("Error", "Invalid file type entered.")

# Modify your GUI creation function to include the console text area
def create_gui():
    root = tk.Tk()
    root.geometry("700x500")
    root.title("Cyberize Linux 0.6 | @Huckleboard (git) | Ubuntu kit")
    
    # Adding a frame for console output
    console_frame = tk.Frame(root)
    console_frame.pack(fill='both', expand=True)

    # Creating a Text widget in the console frame
    console_output = tk.Text(console_frame, height=10)
    console_output.pack(side="bottom", fill="both", expand=True)


    tree = ttk.Treeview(root)

    categories = {
        "User & System Info": ["List Users", "List System Info", "List User Groups", "Show Hardware Info"],
        "Security Settings": ["Update System", "Configure Firewall", "Check Firewall Status", "List Open Ports", "List Running Services", "Disable Guest Account", "Install Antivirus", "Check Unnecessary Packages", "Remove Unnecessary Packages", "List Scheduled Tasks", "Secure SSH Configuration", "Check for Rootkits", "Enforce Password Policies", "Manage User Accounts", "Backup System", "Monitor Network", "Monitor Logs", "Securely Delete Files", "Manage Services", "Configure Secure Boot", "Check Disk Space", "Perform Security Audit", "Manage SSH Keys", "Check File Permissions", "Monitor System Resources", "Show Software Inventory", "File Search"],
        "Maintenance": ["Clean Old Kernels", "Remove Orphaned Packages", "Clear Cache"],
        "Monitoring": ["System Resource Monitor", "Show Detailed System Info"],
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
        "Clean Old Kernels": clean_old_kernels,
        "Remove Orphaned Packages": remove_orphaned_packages,
        "Clear Cache": clear_cache,
        "System Resource Monitor": lambda: system_resource_monitor(console_output),  # This will need a button or a refresh mechanism
        "Show Detailed System Info": lambda: show_detailed_system_info(console_output),
    }

    for category, tools_list in categories.items():
        parent = tree.insert("", "end", text=category)
        for tool in tools_list:
            tree.insert(parent, "end", text=tool)
    
    tree.pack(fill="both", expand=True)
    tree.bind("<Double-Button-1>", lambda event, tree=tree, tools=tools, console_output=console_output: execute_selected_tool(tree, tools, console_output, event))
    execute_button = ttk.Button(root, text="Execute Selected Tool", command=lambda tree=tree, tools=tools, console_output=console_output: execute_selected_tool(tree, tools, console_output))
    execute_button.pack(pady=10)

    root.mainloop()

def execute_selected_tool(tree, tools, output_widget, event=None):
    selected_item = tree.selection()
    if selected_item:
        tool_name = tree.item(selected_item, 'text')
        if tool_name in tools:
            tool_function = tools[tool_name]
            # Check the number of arguments that the tool function expects.
            num_args = tool_function.__code__.co_argcount
            if num_args == 0:
                tool_function()  # Call the tool function without arguments.
            else:
                tool_function(output_widget)  # Pass the output_widget to the tool function.



if __name__ == "__main__":
    create_gui()
