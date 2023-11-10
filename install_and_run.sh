#!/bin/bash

# Update package lists
apt-get update

# Install Python3 and Python3-pip if they are not installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Installing now..."
    apt-get install -y python3
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip for Python3 is not installed. Installing now..."
    apt-get install -y python3-pip
fi

# Install tkinter for Python3
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "tkinter for Python3 is not installed. Installing now..."
    apt-get install -y python3-tk
fi

# Install sudo if not installed
if ! command -v sudo &> /dev/null; then
    echo "sudo is not installed. Installing now..."
    apt-get install -y sudo
fi

# Install UFW firewall if not installed
if ! command -v ufw &> /dev/null; then
    echo "UFW is not installed. Installing now..."
    apt-get install -y ufw
fi

# Install lsof for listing open ports if not installed
if ! command -v lsof &> /dev/null; then
    echo "lsof is not installed. Installing now..."
    apt-get install -y lsof
fi

# Install lshw for listing hardware info if not installed
if ! command -v lshw &> /dev/null; then
    echo "lshw is not installed. Installing now..."
    apt-get install -y lshw
fi

# Install Lynis for security auditing if not installed
if ! command -v lynis &> /dev/null; then
    echo "Lynis is not installed. Installing now..."
    apt-get install -y lynis
fi

# Install RKHunter for rootkit detection if not installed
if ! command -v rkhunter &> /dev/null; then
    echo "RKHunter is not installed. Installing now..."
    apt-get install -y rkhunter
fi


echo "All prerequisites should be installed now."
