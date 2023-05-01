import scapy.all as scapy
import secrets
import random
import config
from cryptography.fernet import Fernet
from encryption import KEY #  shared key for decryption



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

def send_pkt(msg, seqNum, id, mLen, payload_len):
    '''
    Send packet is called to send message.
    msg: 100 byte chunks of the message
    seqNum: the current sequence number 
    id: identifier used to group packets at receiver
    mLen: used to determine when the last packet is sent
    payload_len: actual size of payload - padding
    '''
    pkt = scapy.IP(src = IP_SRC, dst = IP_DST, proto = PROTO_ICMP)
    pkt = pkt/scapy.ICMP(type = ECHO_ICMP_TYPE, code = ECHO_ICMP_CODE)
    pkt = pkt/CovertHeader()
    pkt = pkt/msg
    print('The current sequence number is: ', seqNum)
    pkt[CovertHeader].seqNum = seqNum
    pkt[CovertHeader].ID = id
    pkt[CovertHeader].len = 128 + payload_len  ## Need to be able to distinguish between regular pings and covert pings. MSB is always 1
    if mLen == 0:
        pkt[CovertHeader].final = 1 # if message length is 0, then this is our final packet.
    sendSock.send(pkt)
    print(f'Sent packet with payload length: {payload_len} and ID: {id}')

# IPs, protocol, type, and code
IP_SRC = '127.0.0.1'
IP_DST = input("Enter Destination Address (Recommend 127.0.0.1)")
PROTO_ICMP = 1 #'\x01'
ECHO_ICMP_TYPE = 8 #'\x08'
ECHO_ICMP_CODE = 0 #'\x00'

scapy.conf.L3socket = scapy.L3RawSocket
sendSock = scapy.conf.L3socket()

msg = input('Enter your message:  ')

#encyrption
f = Fernet(KEY)

# process message
# encode message to bytes

# this didn't work but I tried to encrypt the message
# encMsg = f.encrypt(msg.encode())

encMsg = msg.encode()
print('message length: ', len(encMsg),  'bytes')

# if the message is over  80 bytes, this splits it into chunks which are stored in a list
# each string in the list is encoded and sent to the server
msgList = []
done = False
chunkStart = 0
chunkEnd = 80


while not done:
    
    msgChunk = encMsg[chunkStart:chunkEnd]
    chunkStart += 80
    chunkEnd += 80
    msgList.append(msgChunk) # encrypts the message chunk before adding it to the list to be sent
    if chunkStart > len(encMsg):
            done = True
            break
    elif chunkEnd > len(encMsg):
        msgList.append(encMsg[chunkStart:])
        done = True


# Loop sending 100 bytes at a time.
# HINT: secrets module can be used to add randomized padding for the only or last packet 
mLen = len(encMsg)
seqNum = random.randint(0, 32766) # 32766 is 2^15 - 1
id = random.randint(1, 255)

for i in range(len(msgList)):
    curMsg = msgList[i]
    szPayload = len(msgList[i])
    mLen = 1 if i < len(msgList) - 1 else 0 # goes to 0 if it's the last packet to signal the server to stop looking

    send_pkt(curMsg, seqNum, id, mLen, szPayload)