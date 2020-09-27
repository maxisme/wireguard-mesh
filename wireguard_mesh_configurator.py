#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: Wireguard Mesh Configurator
Dev: K4YT3X
Date Created: October 10, 2018
Last Modified: May 16, 2019

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
(C) 2018-2019 K4YT3X
"""
from avalon_framework import Avalon
import json
import os
import re
import readline
import subprocess
import sys

STORE_PATH = '/wg.json'
COMMANDS = [
    'show',
    'add',
    'delete',
    'save'
]
SUBNET = "/32"
BASE = "10.0.0."
WG="wg0"
PORT="51978"


class Utilities:
    """ Useful utilities

    This class contains a number of utility tools.
    """

    @staticmethod
    def execute(command, input_value=''):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = process.communicate(input=input_value)[0]
        return output.decode().replace('\n', '')


class ShellCompleter(object):
    """ A Cisco-IOS-like shell completer

    This is a Cisco-IOS-like shell completer, that is not
    case-sensitive. If the command typed is not ambiguous,
    then execute the only command that matches. User does
    not have to enter the entire command.
    """

    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [s for s in self.options if s and s.lower().startswith(text.lower())]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state]
        except IndexError:
            return None


class Peer:
    """ Peer class

    Each object of this class represents a peer in
    the wireguard mesh network.
    """

    def __init__(self, address, public_address, listen_port, private_key, keep_alive):
        self.address = address
        self.public_address = public_address
        self.listen_port = listen_port
        self.private_key = private_key
        self.keep_alive = keep_alive


class WireGuard:
    """ WireGuard utility controller

    This class handles the interactions with the wg binary,
    including:

    - genkey
    - pubkey
    - genpsk
    """

    def __init__(self):
        pass

    def genkey(self):
        """ Generate WG private key

        Generate a new wireguard private key via
        wg command.
        """
        return Utilities.execute(['wg', 'genkey'])

    def pubkey(self, public_key):
        """ Convert WG private key into public key

        Uses wg pubkey command to convert the wg private
        key into a public key.
        """
        return Utilities.execute(['wg', 'pubkey'], input_value=public_key.encode('utf-8'))

    def genpsk(self):
        """ Generate a random base64 psk
        """
        return Utilities.execute(['wg', 'genpsk'])


class ProfileManager(object):
    """ Profile manager

    Each instance of this class represents a profile,
    which is a complete topology of a mesh / c/s network.
    """

    def __init__(self):
        """ Initialize peers list
        """
        self.peers = []

    def json_load_profile(self, profile_path):
        """ Load profile to JSON file

        Dumps each peer's __dict__ to JSON file.
        """
        self.peers = []
        Avalon.debug_info(f'Loading profile from: {profile_path}')
        with open(profile_path, 'rb') as profile:
            loaded_profiles = json.load(profile)
            profile.close()

        for p in loaded_profiles['peers']:
            peer = Peer(p['address'], p['public_address'], p['listen_port'], p['private_key'],
                        keep_alive=p['keep_alive'])
            pm.peers.append(peer)

    def json_save_profile(self, profile_path):
        """ Save current profile to a JSON file
        """

        # Finally, write the profile into the destination file
        Avalon.debug_info(f'Writing profile to: {profile_path}')

        peers_dict = {}
        peers_dict['peers'] = []

        for peer in pm.peers:
            peers_dict['peers'].append(peer.__dict__)

        with open(profile_path, 'w') as profile:
            json.dump(peers_dict, profile, indent=4)
            profile.close()


def print_peer_config(peer):
    """ Print the configuration of a specific peer

    Input takes one Peer object.
    :type peer: Peer
    """
    Avalon.info(f'{peer.address} information summary:')
    if peer.address:
        print(f'Address: {peer.address}')
    if peer.public_address:
        print(f'Public Address: {peer.public_address}')
    print(f'Private Key: {peer.private_key}')


def add_peer():
    """ Enroll a new peer

    Gets all the information needed to generate a
    new Peer class object.
    """

    # Get peer tunnel address
    peer: Peer
    max_peer = 0
    for peer in pm.peers:
        addr = peer.address.replace(SUBNET, "")
        addr_array = addr.split(".")
        peer_num = int(addr_array[-1].replace(".", ""))
        if peer_num > max_peer:
            max_peer = peer_num

    address = BASE + str(max_peer + 1) + SUBNET

    Avalon.info(f"New address: {address}")

    # Get peer public IP address
    while True:
        public_address = Avalon.gets('Public address (leave empty if client only) [IP|FQDN]: ')

        # Check if public_address is valid IP or FQDN
        valid_address = False
        if re.match('^(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?$', public_address) is not None:
            valid_address = True
        if re.match('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', public_address) is not None:
            valid_address = True

        if not valid_address and public_address != '':  # field not required
            Avalon.error('Invalid public address address entered')
            Avalon.error('Please enter an IP address or FQDN')
            continue
        break

    peer = Peer(address, public_address, PORT, wg.genkey(), keep_alive=True if not public_address else False)
    pm.peers.append(peer)
    print_peer_config(peer)


def delete_peer(address):
    """ Delete a peer

    Delete a specific peer from the peer list.
    """
    for peer in pm.peers:
        if peer.address == address:
            pm.peers.remove(peer)


def generate_configs(output_path):
    """ Generate configuration file for every peer

    This function reads the PEERS list, generates a
    configuration file for every peer, and export into
    the CONFIG_OUTPUT directory.
    """
    if len(pm.peers) == 0:
        Avalon.warning('No peers configured, exiting')
        exit(0)
    if len(pm.peers) == 1:
        Avalon.warning('Only one peer configured')

    Avalon.info('Generating configuration files')

    # Abort is destination is a file / link
    if os.path.isfile(output_path) or os.path.islink(output_path):
        Avalon.warning('Destination path is a file / link')
        Avalon.warning('Aborting configuration generation')
        return 1

    # Ask if user wants to create the output directory if it doesn't exist
    if not os.path.isdir(output_path):
        if Avalon.ask('Output directory doesn\'t exist. Create output directory?', True):
            os.mkdir(output_path)
        else:
            Avalon.warning('Aborting configuration generation')
            return 1

    CMDS = []
    LOCAL_CMDS = []
    # Iterate through all peers and generate configuration for each peer
    peer: Peer
    for peer in pm.peers:
        Avalon.debug_info(f'Generating configuration file for {peer.address}')
        path = f'{output_path}/{peer.address.split("/")[0]}.conf'
        with open(path, 'w') as config:

            # Write Interface configuration
            config.write('[Interface]\n')
            config.write(f'PrivateKey = {peer.private_key}\n')
            if peer.address != '':
                config.write(f'Address = {peer.address}\n')
            if peer.listen_port != '':
                config.write(f'ListenPort = {peer.listen_port}\n')

            # Write peers' information
            p: Peer
            for p in pm.peers:
                if p.address == peer.address:
                    # Skip if peer is self
                    continue
                config.write('\n[Peer]\n')
                print(p.private_key)
                config.write(f'PublicKey = {wg.pubkey(p.private_key)}\n')
                config.write(f'AllowedIPs = {p.address}\n')
                if p.public_address != '':
                    config.write(f'Endpoint = {p.public_address}:{p.listen_port}\n')
                if peer.keep_alive:
                    config.write('PersistentKeepalive = 25\n')
        if peer.public_address:
            CMDS.append(["scp", path, f"root@{peer.public_address}:/etc/wireguard/{WG}.conf"])
        else:
            LOCAL_CMDS.append(f"cp {path} /etc/wireguard/{WG}.conf")

    # run wireguard update commands
    for peer in pm.peers:
        up_down = [f"wg-quick up {WG}", f"systemctl enable wg-quick@{WG}", f"wg-quick down {WG}", f"wg-quick up {WG}", "wg"]
        if peer.public_address:
            for cmd in up_down:
                CMDS.append(["ssh", f"root@{peer.public_address}"] + [cmd])
        else:
            LOCAL_CMDS.append(up_down)

    for cmd in CMDS:
        print(f"Running: {' '.join(cmd)}")
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        print(stdout)

    if LOCAL_CMDS:
        print("\n\nRun these commands locally:")
        print(LOCAL_CMDS)
        for c in LOCAL_CMDS:
            if isinstance(c, list):
                print(c[0])
            else:
                print(c)
        print("\n\n")
    pm.json_save_profile(STORE_PATH)
    exit(0)


def print_help():
    """ Print help messages
    """
    help_lines = [
        f'\n{Avalon.FM.BD}Commands are not case-sensitive{Avalon.FM.RST}',
        'show',
        'add',
        'delete',
        'save',
        '',
    ]
    for line in help_lines:
        print(line)


def command_interpreter(commands):
    """ WGC shell command interpreter

    This function interprets commands from CLI or
    the interactive shell, and passes the parameters
    to the corresponding functions.
    """
    try:
        # Try to guess what the user is saying
        possibilities = [s for s in COMMANDS if s.lower().startswith(commands[1])]
        if len(possibilities) == 1:
            commands[1] = possibilities[0]

        if commands[1].replace(' ', '') == '':
            result = 0
        elif commands[1].lower() == 'help':
            print_help()
            result = 0
        elif commands[1].lower() == 'show':
            for peer in pm.peers:
                print_peer_config(peer)
            result = 0
        elif commands[1].lower() == 'add':
            result = add_peer()
        elif commands[1].lower() == 'delete':
            result = delete_peer(commands[2])
        elif commands[1].lower() == 'save':
            result = generate_configs("/tmp/wg-configs/")
        elif len(possibilities) > 0:
            Avalon.warning(f'Ambiguous command \"{commands[1]}\"')
            print('Use \"Help\" command to list available commands')
            result = 1
        else:
            Avalon.error('Invalid command')
            print('Use \"Help\" command to list available commands')
            result = 1
        return result
    except IndexError:
        Avalon.error('Invalid arguments')
        print('Use \"Help\" command to list available commands')
        result = 0


def main():
    """ WireGuard Mesh Configurator main function

    This function controls the main flow of this program.
    """

    try:
        if sys.argv[1].lower() == 'help':
            print_help()
            exit(0)
    except IndexError:
        pass

    # Begin command interpreting
    pm.json_load_profile(STORE_PATH)
    # Set command completer
    completer = ShellCompleter(COMMANDS)
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    # Launch interactive trojan shell
    prompt = f'{Avalon.FM.BD}[WGC]> {Avalon.FM.RST}'
    while True:
        command_interpreter([''] + input(prompt).split(' '))


if __name__ == '__main__':
    # Create global object for WireGuard handler
    wg = WireGuard()

    # Create global object for profile manager
    pm = ProfileManager()

    # Launch main function
    main()
