# Network Scanner and Enumerator

## Description
This project is a network scanner and enumerator developed in Python using the Tkinter library for the graphical user interface (GUI). It provides a user-friendly interface for scanning common ports, detecting operating systems, enumerating SMB shares and users, and enumerating FTP directories on a target IP address.

## Features
- **Normal Scan**: Scan common ports on a target IP address.
- **Ports Scan**: Perform a comprehensive scan of all ports on a target IP address.
- **OS Detection**: Detect the operating system running on a target IP address.
- **SMB Enumeration**: Enumerate SMB shares and users on a target IP address.
- **FTP Enumeration**: Enumerate files in the FTP directory on a target IP address.

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/francescobrina/network_scanner_enum.git
   ```

2. Navigate to the project directory:
   ```
   cd network-scanner-enum
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
1. Run the main script:
   ```
   python main.py
   ```

2. Enter the IP address of the target machine.
3. Select the scan type from the dropdown menu.
4. Click on the "Start Scan" button to initiate the scan.
5. View the scan results in the output text area.

## Contributing
Contributions are welcome! Please feel free to fork the repository and submit pull requests to contribute to this project.
