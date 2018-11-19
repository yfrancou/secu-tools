#!/bin/bash
# extract_pcap_streams.sh: Extract TCP streams from a PCAP file
# Need to have 'tshark' installed

# define usage function
usage(){
    echo "Usage: $0 pcap_filename"
    exit 1
}

# define is_file_exits function
# $f -> store argument passed to the script
is_file_exits(){
    local f="$1"
    [[ -f "$f" ]] && return 0 || return 1
}
# invoke  usage
# call usage() function if filename not supplied
[[ $# -eq 0 ]] && usage

# Invoke is_file_exits
if ( is_file_exits "$1" )
then

    END=$(tshark -r $1 -T fields -e tcp.stream | sort -n | tail -1)
    for ((i=0;i<=END;i++))
    do
        echo "$i/$(($END))"
        tshark -r $1 -qz follow,tcp,ascii,$i > $1-$i.stream
    done

else
    echo "File '$1' not found"
fi


