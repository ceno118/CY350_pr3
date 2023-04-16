import scapy.all as scapy
import config
from sys import exit

#You do not need to use the header below
# (you can delete it if you don't want/need it)
class CovertHeader(scapy.Packet):
    '''This class defines a header for use with your encrypted message.
    You may define additional header fields if you want or need to. The seqNum 
    field is used to help reorder messages, and len is the length of data 
    following this header. 
    
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       ID      |      LEN      |F|            SEQNUM           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            Fig. CovertHeader
    '''
    name = "Covert Comms Channel Header"
    fields_desc = [scapy.ByteField("ID", 0), # ID used to pair packets
                   scapy.ByteField("len", 0), # length of data 
                   scapy.BitField("final", 0, 1), # bit set to 1 for final packet
                   scapy.BitField("seqNum", 0, 15) ] # sequence number of current message

def process_icmp_only(pkt):
    '''
    Found that BPF filtering using the 'filter=' parameter is not working, we will filter the packets
    one at a time as we receive them (this is slower, but should be fast enough in our case)
    '''
    # TODO: Here is where you will begin processing packets - you are only interested in ICMP Echos
      
#we need to change the default layer 3 socket type to catch the loopback packets
scapy.conf.L3socket = scapy.L3RawSocket
rcvSock = scapy.conf.L3socket()

# You likely don't need to make changes to this loop
while True:
    try:
        #Capture one packet at a time, sending each to the process_icmp_only function defined above for processing/filtering
        rcvSock.sniff(count=1, prn=process_icmp_only)
    except KeyboardInterrupt as e:
        'Received keyboard interrupt, ending program'
        exit()
    except:
        'Encountered exception while sniffing, continuing...'
        continue
