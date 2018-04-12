import struct
import time
import socket
import select

MAX_HOP = 32
port = 33434
msg = 'measurement for class project. questions to student xxt79@case.edu or professor mxr136@case.edu' + 'X' * 1377
payload = bytes(msg, 'ascii')
VERBOSE = True


def main(targets, results):
    """
    main function
    :param targets: is the target websites to visit
    :return: tuple of (target domain, hop_count, rtt, geological_dist)
    """
    targets_list = open(targets).read().splitlines()
    result = open(results, 'w')

    for target in targets_list:
        hop_count, rtt, size_of_initial_msg = hop_count_and_rtt_of(target)
        result.write('%s, %s, %s, %s\n' % (target, hop_count, rtt, size_of_initial_msg))

    print('Probing complete')
    result.close()


def set_socket(ttl):
    """
    sockets setup
    :param ttl: time-to-live
    :return: both rcv and snd sockets
    """
    # raw socket that receives ICMP msg
    rcv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    snd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # set socket
    rcv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    snd_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    timeout = struct.pack("ll", 5, 0)
    rcv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

    return rcv_socket, snd_socket


def hop_count_and_rtt_of(dest_name):
    """
    counts hops and rtt of one website
    :param dest_name: domain of the website
    :return: the hop count and rtt from my computer to destination
    """
    ttl = MAX_HOP
    rtt = time.time()

    while True:

        dest_addr = socket.gethostbyname(dest_name)
        rcv_socket, snd_socket = set_socket(ttl)
        rcv_socket.bind(("", port))

        select_status = select.select([rcv_socket], [], [], 2)

        node_addr = None
        node_name = None
        tries = 3
        reachable = False

        snd_socket.sendto(payload, (dest_name, port))

        while not reachable and tries > 0 and select_status:
            try:
                # get the address from receiving socket
                icmp_packet, node_addr = rcv_socket.recvfrom(512)
                reachable = True
                node_addr = node_addr[0]

                try:
                    # reverse DNS lookup
                    node_name = socket.gethostbyaddr(node_addr)[0]
                except socket.error:
                    # if it fails, we'll substitute it with the address
                    node_name = node_addr

            except socket.error:
                tries -= 1
                print("Failed to receive from socket")

        if not reachable:
            print("Site unreachable after 3 tries")
            return "Unreachable", "Unreachable"

        # unpack ip header to get ttl
        ip_header_packed = icmp_packet[28:48]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_packed)
        node_ttl = ip_header[5]
        ttl = node_ttl

        snd_socket.close()
        rcv_socket.close()

        """ 
        # debugging aid, prints every router on the way
        if node_addr is not None:
            curr_host = "%s : %s" % (node_addr, node_name)
        else:
            curr_host = "*"
        print("%d\t%s" % (ttl, curr_host))
        """

        # exit the loop when reached dest or exceeded max # of hops
        if node_addr == dest_addr or node_ttl <= 0:
            hop_count = MAX_HOP - node_ttl

            boomerang_msg = []
            # the data after the 56th index of the packet is usually the initial data I sent. Observed with Wireshark
            if icmp_packet[56:] in payload:
                # this is the original message contained in the icmp
                boomerang_msg = icmp_packet[56:]

            rtt = int((time.time() - rtt)*1000)
            print('<Sys>: Site: %s, IP: %s HOP count: %s, RTT: %d ms, bytes of initial message in ICMP: %d ' % (
                  dest_name, dest_addr, hop_count, rtt, len(boomerang_msg)))
            return hop_count, rtt, len(boomerang_msg)


if __name__ == "__main__":
    main("targets.txt", "results.csv")
