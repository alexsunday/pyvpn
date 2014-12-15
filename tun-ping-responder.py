##
# This script attaches to a tun interface and answer IPv6 and IPv4 echo 
# requests ("ping").
#
# This is companion script to the "tun/tap in Windows" at openwsn.org.
#
# It is an extended version of the following code:
# - https://gist.github.com/glacjay/586892
# - http://www.varsanofiev.com/inside/using_tuntap_under_windows.htm
#
# \author Thomas Watteyne <watteyne@eecs.berkeley.edu>, March 2013.
#
# The OpenWSN license applies to this file.
#

import _winreg as reg
import win32file
import win32event
import pywintypes
import threading
import time

#============================ defines =========================================

## IPv4 configuration of your TUN interface (represented as a list of integers)
TUN_IPv4_ADDRESS    = [ 10,  2,0,1] ##< The IPv4 address of the TUN interface.
TUN_IPv4_NETWORK    = [ 10,  2,0,0] ##< The IPv4 address of the TUN interface's network.
TUN_IPv4_NETMASK    = [255,255,0,0] ##< The IPv4 netmask of the TUN interface.

## Key in the Windows registry where to find all network interfaces (don't change, this is always the same)
ADAPTER_KEY         = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'

## Value of the ComponentId key in the registry corresponding to your TUN interface.
TUNTAP_COMPONENT_ID = 'tap0901'

#============================ helpers =========================================

#=== tun/tap-related functions

def get_tuntap_ComponentId():
    '''
    \brief Retrieve the instance ID of the TUN/TAP interface from the Windows
        registry,
    
    This function loops through all the sub-entries at the following location
    in the Windows registry: reg.HKEY_LOCAL_MACHINE, ADAPTER_KEY
      
    It looks for one which has the 'ComponentId' key set to
    TUNTAP_COMPONENT_ID, and returns the value of the 'NetCfgInstanceId' key.
    
    \return The 'ComponentId' associated with the TUN/TAP interface, a string
        of the form "{A9A413D7-4D1C-47BA-A3A9-92F091828881}".
    '''
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, ADAPTER_KEY) as adapters:
        try:
            for i in xrange(10000):
                key_name = reg.EnumKey(adapters, i)
                with reg.OpenKey(adapters, key_name) as adapter:
                    try:
                        component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                        if component_id == TUNTAP_COMPONENT_ID:
                            return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                    except WindowsError, err:
                        pass
        except WindowsError, err:
            pass

def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method;

def TAP_CONTROL_CODE(request, method):
    return CTL_CODE(34, request, method, 0)

TAP_IOCTL_SET_MEDIA_STATUS        = TAP_CONTROL_CODE( 6, 0)
TAP_IOCTL_CONFIG_TUN              = TAP_CONTROL_CODE(10, 0)

def openTunTap():
    '''
    \brief Open a TUN/TAP interface and switch it to TUN mode.
    
    \return The handler of the interface, which can be used for later
        read/write operations.
    '''
    
    # retrieve the ComponentId from the TUN/TAP interface
    componentId = get_tuntap_ComponentId()
    print('componentId = {0}'.format(componentId))
    
    # create a win32file for manipulating the TUN/TAP interface
    tuntap = win32file.CreateFile(
        r'\\.\Global\%s.tap' % componentId,
        win32file.GENERIC_READ    | win32file.GENERIC_WRITE,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
        None,
        win32file.OPEN_EXISTING,
        win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
        None
    )
    print('tuntap      = {0}'.format(tuntap.handle))
    
    # have Windows consider the interface now connected
    win32file.DeviceIoControl(
        tuntap,
        TAP_IOCTL_SET_MEDIA_STATUS,
        '\x01\x00\x00\x00',
        None
    )
    
    # prepare the parameter passed to the TAP_IOCTL_CONFIG_TUN commmand.
    # This needs to be a 12-character long string representing
    # - the tun interface's IPv4 address (4 characters)
    # - the tun interface's IPv4 network address (4 characters)
    # - the tun interface's IPv4 network mask (4 characters)
    configTunParam  = []
    configTunParam += TUN_IPv4_ADDRESS
    configTunParam += TUN_IPv4_NETWORK
    configTunParam += TUN_IPv4_NETMASK
    configTunParam  = ''.join([chr(b) for b in configTunParam])
    
    # switch to TUN mode (by default the interface runs in TAP mode)
    win32file.DeviceIoControl(
        tuntap,
        TAP_IOCTL_CONFIG_TUN,
        configTunParam,
        None
    )
    
    # return the handler of the TUN interface
    return tuntap

#=== misc

def formatByteList(byteList):
    '''
    \brief Format a byte list into a string, which can then be printed.
    
    For example:
       [0x00,0x11,0x22] -> '(3 bytes) 001122'
    
    \param[in] byteList A list of integer, each representing a byte.
    
    \return A string representing the byte list.
    '''
    return '({0} bytes) {1}'.format(len(byteList),''.join(['%02x'%b for b in byteList]))

def carry_around_add(a, b):
    '''
    \brief Helper function for checksum calculation.
    '''
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(byteList):
    '''
    \brief Calculate the checksum over a byte list.
    
    This is the checksum calculation used in e.g. the ICMPv6 header.
    
    \return The checksum, a 2-byte integer.
    '''
    s = 0
    for i in range(0, len(byteList), 2):
        w = byteList[i] + (byteList[i+1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

#============================ threads =========================================

class ReadThread(threading.Thread):
    '''
    \brief Thread which continously reads input from a TUN interface.
    
    If that input is an IPv4 or IPv6 echo request (a "ping" command) issued to
    any IP address in the virtual network behind the TUN interface, this thread
    answers with the appropriate echo reply.
    '''
    
    ETHERNET_MTU        = 1500
    IPv6_HEADER_LENGTH  = 40
    
    def __init__(self,tuntap,transmit):
    
        # store params
        self.tuntap               = tuntap
        self.transmit             = transmit
        
        # local variables
        self.goOn                 = True
        self.overlappedRx         = pywintypes.OVERLAPPED()
        self.overlappedRx.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        # initialize parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name                 = 'readThread'
    
    def run(self):
        
        rxbuffer = win32file.AllocateReadBuffer(self.ETHERNET_MTU)
        
        while self.goOn:
            
            # wait for data
            l, p = win32file.ReadFile(self.tuntap, rxbuffer, self.overlappedRx)
            win32event.WaitForSingleObject(self.overlappedRx.hEvent, win32event.INFINITE)
            self.overlappedRx.Offset = self.overlappedRx.Offset + len(p)
            
            # convert input from a string to a byte list
            p = [ord(b) for b in p]
            
            # print input
            #print 'in: l: {0} p: {1}'.format(l,formatByteList(p))
            
            # parse received packet
            if (p[0]&0xf0)==0x40:
                # IPv4
                
                # keep only IPv4 packet
                total_length = 256*p[2]+p[3]
                p = p[:total_length]
                
                if p[9]==0x01:
                    # ICMPv4
                    
                    if p[20]==0x08:
                        # IPv4 echo request
                    
                        # print
                        print 'Received IPv4 echo request'
                        
                        # create echo reply
                        echoReply = self._createIpv4EchoReply(p)
                        
                        # send over interface
                        self.transmit(echoReply)
                        
                        # print
                        print 'Transmitted IPv4 echo reply'
                    
                    elif p[20]==0x00:
                        
                        # print
                        print 'Received IPv4 echo reply'
                
            elif (p[0]&0xf0)==0x60:
                # IPv6
                
                # keep only IPv6 packet
                payload_length = 256*p[4]+p[5]
                p = p[:payload_length+self.IPv6_HEADER_LENGTH]
                
                if p[6]==0x3a:
                    # ICMPv6
                    
                    if p[40]==0x80:
                        # IPv6 echo request
                        
                        # print
                        print 'Received IPv6 echo request'
                        
                        # create echo reply
                        echoReply = self._createIpv6EchoReply(p)
                        
                        # send over interface
                        self.transmit(echoReply)
                        
                        # print
                        print 'Transmitted IPv6 echo reply'
                    
                    elif p[40]==0x81:
                        
                        # print
                        print 'Received IPv6 echo reply'
    
    #======================== public ==========================================
    
    def close(self):
        self.goOn = False
    
    #======================== private =========================================
    
    def _createIpv4EchoReply(self,echoRequest):
        
        # invert addresses, change "echo request" type to "echo reply"
        echoReply       = echoRequest[:12]   + \
                          echoRequest[16:20] + \
                          echoRequest[12:16] + \
                          [0x00]             + \
                          echoRequest[21:]
        
        # recalculate checksum
        echoReply[22]   = 0x00
        echoReply[23]   = 0x00
        crc     = checksum(echoReply[20:])
        echoReply[22]   = (crc&0x00ff)>>0
        echoReply[23]   = (crc&0xff00)>>8
        
        return echoReply
    
    def _createIpv6EchoReply(self,echoRequest):
        
        # invert addresses, change "echo request" type to "echo reply"
        echoReply       = echoRequest[:8]    + \
                          echoRequest[24:40] + \
                          echoRequest[8:24]  + \
                          [129]              + \
                          echoRequest[41:]
        
        # recalculate checksum
        pseudo          = []
        pseudo         += echoRequest[24:40]               # source address
        pseudo         += echoRequest[8:24]                # destination address
        pseudo         += [0x00]*3+[len(echoRequest[40:])] # upper-layer packet length
        pseudo         += [0x00]*3                         # zero
        pseudo         += [58]                             # next header
        pseudo         += echoRequest[40:]                 # ICMPv6 header+payload
        
        pseudo[40]      = 129                              # ICMPv6 type = echo reply
        pseudo[42]      = 0x00                             # reset CRC for calculation
        pseudo[43]      = 0x00                             # reset CRC for calculation
        
        crc             = checksum(pseudo)
        
        echoReply[42]   = (crc&0x00ff)>>0
        echoReply[43]   = (crc&0xff00)>>8
        
        return echoReply

class WriteThread(threading.Thread):
    '''
    \brief Thread with periodically sends IPv4 and IPv6 echo requests.
    '''
    
    SLEEP_PERIOD   = 1
    
    def __init__(self,tuntap):
    
        # store params
        self.tuntap               = tuntap
        
        # local variables
        self.goOn                 = True
        self.createIPv6           = False
        self.overlappedTx         = pywintypes.OVERLAPPED()
        self.overlappedTx.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        # initialize parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name                 = 'writeThread'
    
    def run(self):
        
        while self.goOn:
            
            # sleep a bit
            time.sleep(self.SLEEP_PERIOD)
            
            # create an echo request
            dataToTransmit = self._createEchoRequest()
            
            # transmit
            self.transmit(dataToTransmit)
    
    #======================== public ==========================================
    
    def close(self):
        self.goOn = False
    
    def transmit(self,dataToTransmit):
        
        # convert to string
        dataToTransmit  = ''.join([chr(b) for b in dataToTransmit])
        
        # write over tuntap interface
        win32file.WriteFile(self.tuntap, dataToTransmit, self.overlappedTx)
        win32event.WaitForSingleObject(self.overlappedTx.hEvent, win32event.INFINITE)
        self.overlappedTx.Offset = self.overlappedTx.Offset + len(dataToTransmit)
    
    #======================== private =========================================
    
    def _createEchoRequest(self):
        '''
        \brief Create an echo request.
        
        This function switches between IPv4 and IPv6 echo requests.
        '''
        
        # toggle createIPv6 flag
        self.createIPv6 = not self.createIPv6
        
        # create IPv4 or IPv6 echo request
        if self.createIPv6:
            print 'Transmitting IPv6 echo request'
            return self._createIPv6echoRequest()
        else:
            print 'Transmitting IPv4 echo request'
            return self._createIPv4echoRequest()
    
    def _createIPv4echoRequest(self):
        '''
        \brief Create a value IPv4 echo request.
        '''
        
        echoRequest  = []
        
        # IPv4 header
        echoRequest    += [0x45]                 # Version | IHL
        echoRequest    += [0x00]                 # DSCP | ECN
        echoRequest    += [0x00,60]              # Total Length (20 for IPv4 + 40 ICMPv4)
        echoRequest    += [0x00,0x00]            # Identification
        echoRequest    += [0x00,0x00]            # Flags | Fragment Offset
        echoRequest    += [128]                  # TTL
        echoRequest    += [1]                    # Protocol (1==ICMP)
        echoRequest    += [0x00,0x00]            # Header Checksum (to be filled out later)
        echoRequest    += [10,2,0,5]             # Source IP
        echoRequest    += [10,2,0,1]             # Destination IP
        
        # calculate IPv4 Header checksum
        crc             = checksum(echoRequest)
        echoRequest[10] = (crc&0x00ff)>>0
        echoRequest[11] = (crc&0xff00)>>8
        
        # ICMPv4 header
        echoRequest    += [8]                    # type (8==echo request)
        echoRequest    += [0]                    # code
        echoRequest    += [0x00,0x00]            # Checksum (to be filled out later)
        echoRequest    += [0x00,0x00]            # Identifier
        echoRequest    += [0x00,0x00]            # Sequence Number
        
        # ICMPv4 payload
        echoRequest    += [ord('a')+b for b in range(32)]
        
        # calculate ICMPv4 checksum
        crc             = checksum(echoRequest[20:])
        echoRequest[22] = (crc&0x00ff)>>0
        echoRequest[23] = (crc&0xff00)>>8
        
        return echoRequest
    
    def _createIPv6echoRequest(self):
        '''
        \brief Create an IPv6 echo request.
        '''
        
        echoRequest  = []
        
        # IPv6 header
        echoRequest    += [0x60,0x00,0x00,0x00]       # ver, TF
        echoRequest    += [0x00, 40]                  # length
        echoRequest    += [58]                        # Next header (58==ICMPv6)
        echoRequest    += [128]                       # HLIM
        echoRequest    += [0xbb, 0xbb, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x05,]   # source
        echoRequest    += [0xbb, 0xbb, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x01,]   # destination
        
        # ICMPv6 header
        echoRequest    += [128]                       # type (128==echo request)
        echoRequest    += [0]                         # code
        echoRequest    += [0x00,0x00]                 # Checksum (to be filled out later)
        echoRequest    += [0x00,0x04]                 # Identifier
        echoRequest    += [0x00,0x12]                 # Sequence
        
        # ICMPv6 payload
        echoRequest    += [ord('a')+b for b in range(32)]
        
        # calculate ICMPv6 checksum
        pseudo  = []
        pseudo += echoRequest[24:40]                  # source address
        pseudo += echoRequest[8:24]                   # destination address
        pseudo += [0x00]*3+[len(echoRequest[40:])]    # upper-layer packet length
        pseudo += [0x00]*3                            # zero
        pseudo += [58]                                # next header
        pseudo += echoRequest[40:]                    # ICMPv6 header+payload
        
        crc     = checksum(pseudo)
        
        echoRequest[42]   = (crc&0x00ff)>>0
        echoRequest[43]   = (crc&0xff00)>>8
        
        return echoRequest
    
#============================ main ============================================

def main():
    
    #=== open the TUN/TAP interface
    
    tuntap = openTunTap()
    
    #=== start read/write threads
    
    writeThread = WriteThread(tuntap)
    readThread  = ReadThread(tuntap,writeThread.transmit)
    
    readThread.start()
    writeThread.start()
    
    #=== wait for Enter to stop
    
    raw_input("Press enter to stop...\n")
    
    readThread.close()
    writeThread.close()
    win32file.CloseHandle(tuntap)

if __name__ == '__main__':
    main()
