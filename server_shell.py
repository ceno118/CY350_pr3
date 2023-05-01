import scapy.all as scapy
import config
from sys import exit
from cryptography.fernet import Fernet
from encryption import KEY # shared key for decryption


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

finalMsg = ""
f = Fernet(KEY)
def process_icmp_only(pkt):
    '''
    Filter the packets one at a time as received.
    '''
    # Only interested in ICMP packets.
    if pkt.haslayer(scapy.ICMP):
        
        if pkt[scapy.ICMP].type == 8:
        
            pkt[scapy.ICMP].decode_payload_as(CovertHeader)
            print('Received covert ICMP packet, processing')
            global finalMsg
            #finalMsg = finalMsg + f.decrypt(pkt[CovertHeader].load.decode()) # adds the recent decoded packet to the final message
            # above line didn't work for encryption
            finalMsg = finalMsg + pkt[CovertHeader].load.decode()
            if pkt[CovertHeader].final == 1: # checks for the end of the packet sequence and prints then resets the message
                print(finalMsg)
                finalMsg = ""

#we need to change the default layer 3 socket type to catch the loopback packets
scapy.conf.L3socket = scapy.L3RawSocket

rcvSock = scapy.conf.L3socket()
print("Server Running...")
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