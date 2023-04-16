import scapy.all as scapy
import config

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

# Need the correct socket type for capturing packets on loopback
scapy.conf.L3socket = scapy.L3RawSocket
sendSock = scapy.conf.L3socket()

#Enter the rest of your code for your client application to send covert messages

