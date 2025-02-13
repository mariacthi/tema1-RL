#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

trunk_ports = []
port_states = {}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost

    while True:
        # if we are root bridge, we send BPDU to all trunk ports
        if own_bridge_ID is root_bridge_ID and root_bridge_ID != -1 and root_path_cost != -1:
            for port in trunk_ports:
                # BPDU format: the mac multicast address, the root bridge ID,
                # the root path cost, the sender bridge ID
                mac_cast = struct.pack('!BBBBBB', 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
                sender_bridge_ID = struct.pack('!q', own_bridge_ID)
                root_bridge_ID = struct.pack('!q', own_bridge_ID)
                root_path_cost = struct.pack('!I', 0)
                data = mac_cast  + root_bridge_ID + root_path_cost + sender_bridge_ID

                send_to_link(port, len(data), data)
        time.sleep(1)

def is_unicast(mac_address):
    # Check if the MAC address is not broadcast address ff:ff:ff:ff:ff:ff
    mac_binary = bytes.fromhex(mac_address.replace(':', ''))

    if mac_binary == b'\xff\xff\xff\xff\xff\xff':
        return False

    return True

def parse_file(file):
    vlan_list = {}

    # open the configuration file of a switch
    f = open(file, 'r')
    # first line is the switch priority
    switch_priority = f.readline().strip()

    interf = 0
    for line in f:
        line = line.strip()
        # reading the vlan value for each interface
        vlan_list[interf] = line.split()[1]
        interf += 1

    return switch_priority, vlan_list

def handle_BDPU(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface, BPDU_sender_bridge_ID, data):
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    global root_port
    global trunk_ports
    global port_states

    # check if we were the root bridge
    we_were_root = False
    if (root_bridge_ID == own_bridge_ID):
        we_were_root = True

    # if the BPDU is from a switch with a smaller ID,
    # that becomes the root bridge for our switch
    if BPDU_root_bridge_ID < int(root_bridge_ID):
        root_bridge_ID = BPDU_root_bridge_ID
        # the cost is 10 bc all the links are considered to be 100Mbps
        root_path_cost = BPDU_sender_path_cost + 10
        root_port = interface

        # set all trunk ports to "BLOCKING" except the root port
        if we_were_root == True:
            for port in trunk_ports:
                if port != root_port:
                    port_states[port] = "BLOCKING"

        # set the root port to "LISTENING"
        if port_states[root_port] == "BLOCKING":
            port_states[root_port] = "LISTENING"

        # update and forward BPDU to all trunk ports
        for port in trunk_ports:
            data[14:18] = (int(root_path_cost)).to_bytes(4, byteorder='big')
            data[18:26] = (int(own_bridge_ID)).to_bytes(8, byteorder='big')
            send_to_link(port, len(data), data)

    elif BPDU_root_bridge_ID == root_bridge_ID:
        # check if there is a better path to the root bridge
        if interface == root_port and BPDU_sender_path_cost + 10 < root_path_cost:
            root_path_cost = BPDU_sender_path_cost + 10
        elif interface != root_port:
            # check if the port should be a designated port
            if BPDU_sender_path_cost > root_path_cost:
                if port_states[interface] == "BLOCKING":
                    port_states[interface] = "LISTENING"

    # avoid cycles forming
    elif BPDU_sender_bridge_ID == own_bridge_ID:
        port_states[interface] = "BLOCKING"

    else:
        return

    # if we are the root bridge, set all trunk ports to "LISTENING"
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_states[port] = "LISTENING"

def init_resources(interfaces, switch_id):
    global root_bridge_ID, root_path_cost, own_bridge_ID, root_port
    global trunk_ports
    global port_states

    mac_table = {}
    vlan_list = {}

    # read the configuration file of the switch
    path = "configs/switch{}.cfg".format(switch_id)
    switch_priority, vlan_list = parse_file(path)

    for index in vlan_list:
        if (vlan_list[index] == "T"):
            # set trunk ports to "BLOCKING"
            trunk_ports.append(interfaces[index])
            port_states[interfaces[index]] = "BLOCKING"
        else :
            # set access ports to "LISTENING"
            port_states[interfaces[index]] = "LISTENING"

    # initially each switch thinks it is the root bridge
    own_bridge_ID = int(switch_priority)
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    return mac_table, vlan_list

def send_from_access_mode(vlan, vlan_id, interface, entrance, length, data):
    # forward messages when they come from access mode
    if vlan != "T" and int(vlan) == int(vlan_id) and interface != entrance:
        # access - access => send normally
        send_to_link (interface, length, data)
    elif vlan == "T":
        # access - trunk => add vlan tag to the frame
        tagged_frame = data[0:12] + create_vlan_tag(int(vlan_id)) + data[12:]
        send_to_link(interface, len(tagged_frame), tagged_frame)

def send_from_trunk_mode(vlan, interface, entrance, length, data):
        # forward messages when they come from trunk mode
        if vlan == "T" and interface != entrance:
            # trunk - trunk => send normally
            send_to_link(interface, length, data)
        elif vlan != "T":
            # trunk - access => remove vlan tag from the frame
            tagged_bytes = data[12:16]
            x, vlan2 = struct.unpack('!HH', tagged_bytes)
            vlan2 = vlan2 & 0x0FFF
            if int(vlan2) == int(vlan):
                # check if it is the same vlan
                modified_data = data[0:12] + data[16:]
                send_to_link(interface, len(modified_data), modified_data)


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # print("# Starting switch with id {}".format(switch_id), flush=True)
    # print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    mac_table, vlan_list = init_resources(interfaces, switch_id)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    # for i in interfaces:
    #     print(get_interface_name(i))

    # if we are the root bridge, set all trunk ports to "LISTENING"
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_states[port] = "LISTENING"

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # check if the frame is a BPDU
        if dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            BPDU_root_bridge_ID = int.from_bytes(data[6:14], 'big')
            BPDU_sender_path_cost = int.from_bytes(data[14:18], 'big')
            BPDU_sender_bridge_ID = int.from_bytes(data[18:26], 'big')

            handle_BDPU(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface, BPDU_sender_bridge_ID)
            continue

        mac_table[src_mac] = interface
        entrance = -1
        for index in vlan_list :
            if interfaces[index] == interface:
                # find the entrance port and its vlan id
                entrance = interfaces[index]
                vlan_id = vlan_list[index]

        if is_unicast(dest_mac) and dest_mac in mac_table:
            if vlan_id != "T":
                # comes from access mode
                for index in vlan_list:
                    # only send to the port that has the destination MAC
                    if mac_table[dest_mac] == interfaces[index]:
                        send_from_access_mode(vlan_list[index], vlan_id, mac_table[dest_mac], entrance, length, data)

            else :
                # comes from trunk mode
                for index in vlan_list:
                    if mac_table[dest_mac] == interfaces[index]:
                        # check if the port is not in "BLOCKING" state
                        if port_states[interfaces[index]] != "BLOCKING":
                            send_from_trunk_mode(vlan_list[index], mac_table[dest_mac], entrance, length, data)
        else:
            # if the destination MAC is not unicast or it's not the MAC table,
            # then the frame will be sent to every port
            if vlan_id != "T":
                # comes from access mode
                for index in vlan_list:
                    send_from_access_mode(vlan_list[index], vlan_id, interfaces[index], entrance, length, data)
            else :
                # comes from trunk mode
                for index in vlan_list:
                    # check if the port is not in "BLOCKING" state
                    if port_states[interfaces[index]] != "BLOCKING":
                        send_from_trunk_mode(vlan_list[index], interfaces[index], entrance, length, data)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
