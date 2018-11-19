#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Sanitize TCP stream files extracted from PCAP with the bash script 'extract_pcap_streams.sh' // or TShark.

    Example of use: python _sanitize_tshark_streams.py "*.stream"
    Test example:   python _sanitize_tshark_streams.py "test-samples/test_sanitize_tshark_streams.stream"

    If you find the option in TShark to remove natively these packets lengths, please leave a message :)


    It consists to remove lines where packet lengths are present.
    Example:
        80
        CONNECT www.78abcd.com:80  HTTP/1.1
        Host: www.78abcd.com
        Connection: close


            39
        HTTP/1.1 200 Connection established


        1460
        POST /01234567/abcdef.jpg HTTP/1.1
"""

import argparse
import glob


def extract_packet_length(data):
    packet_length = ""
    orig_data = data
    while len(data) > 0 and data[0] in "0123456789":
        packet_length += data[0]
        data = data[1:]

    # Remove the \n after the packet length
    data = data[1:]

    if packet_length.isdigit():
        return (int(packet_length, 10), data)
    return (None, orig_data)


def extract_packet_data(data, length):

    packet_data = ""
    while len(data) > 0 and length > 0:

        # if data[0] != "\r":
        packet_data += data[0]
        length -= 1
        data = data[1:]

    # Remove all \t or \n next to packet_data (normally, we can only see '\n' or '\t\n')
    while len(data) > 0 and data[0] in "\n\t":
        data = data[1:]

    return (packet_data, data)


def main(filenames):

    for filename in filenames:

        # Read tcp stream file
        data = None
        with open(filename, "rb") as f:
            data = f.read()
        if data is None:
            continue

        # Split lines and go to the first line containing packet length (line after the one starting by 'Node1')
        lines = data.split("\n")
        while len(lines) > 0 and not lines[0].startswith("Node 1:"):
            # print "Line:", lines[0]
            lines = lines[1:]
        lines = lines[1:]
        data = "\n".join(lines)

        packet_data = ""
        # print [data]
        while len(data) > 0:
            # print "Packet data:\n%s\n" % ([data])

            (packet_length, data) = extract_packet_length(data)
            if packet_length is None:
                # print "error or EOF (-> '%s')" % (data[:15])
                break

            # print "Packet Length: %d\n" % (packet_length)
            (data_tmp, data) = extract_packet_data(data, packet_length)
            packet_data += data_tmp

        filename_output = filename + "_san"
        with open(filename_output, "wb") as f:
            f.write(packet_data)
            print "%s -> %s" % (filename, filename_output)
    return True


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Sanitize TCP stream files (.stream) from TShark (output to '%%filename%%_san' files)")
    parser.add_argument('pathes', type=str, help='Path(es) of TCP stream files')

    args = parser.parse_args()

    main(glob.glob(args.pathes))
