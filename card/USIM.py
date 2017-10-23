"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2010 Benoit Michau

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""


#################################
# Python library to work on
# USIM card
# communication based on ISO7816 card
# and commands and formats based on UICC card
#
# needs pyscard from:
# http://pyscard.sourceforge.net/
#################################

from card.ICC import UICC, ISO7816
from card.FS import *
from card.utils import *


class USIM(UICC):
    '''
    defines attributes, methods and facilities for ETSI / 3GPP USIM card
    check USIM specifications in 3GPP TS 31.102
    
    inherits (eventually overrides) methods and objects from UICC class
    use self.dbg = 1 or more to print live debugging information
    '''
    
    def __init__(self):
        '''
        initializes like an ISO7816-4 card with CLA=0x00
        and checks available AID (Application ID) read from EF_DIR
        
        initializes on the MF
        '''
        # initialize like a UICC
        ISO7816.__init__(self, CLA=0x00)
        self.AID = []
        if self.dbg:
            print '[DBG] type definition: %s' % type(self)
            print '[DBG] CLA definition: %s' % hex(self.CLA)
        
        # USIM selection from AID
        print '[+] UICC AID found:'
        self.get_AID()
        for aid in self.AID:
            if  tuple(aid[0:5]) == (0xA0, 0x00, 0x00, 0x00, 0x87) \
            and tuple(aid[5:7]) == (0x10, 0x02) :
                usim = self.select( Data=aid, typ='aid')
                if usim is None: 
                    print '[+] USIM AID selection failed'
                else: 
                    print '[+] USIM AID selection succeeded\n'
        
    def get_imsi(self):
        '''
        get_imsi() -> string(IMSI)
        
        reads IMSI value at address [0x6F, 0x07]
        returns IMSI string on success or None on error
        '''
        # select IMSI file
        imsi = self.select([0x6F, 0x07])
        if imsi is None: 
            return None
        # and parse the received data into the IMSI structure
        if 'Data' in imsi.keys() and len(imsi['Data']) == 9:
            return decode_BCD(imsi['Data'])[3:]
        
        # if issue with the content of the DF_IMSI file
        if self.dbg: 
            print '[DBG] %s' % self.coms()
        return None
    
    def authenticate(self, RAND=[], AUTN=[], ctx='3G'):
        '''
        self.authenticate(RAND, AUTN, ctx='3G') -> [key1, key2...], 
        LV parsing style
        
        runs the INTERNAL AUTHENTICATE command in the USIM 
        with the right context:
            ctx = '2G', '3G', 'GBA' ('MBMS' or other not supported at this time)
            RAND and AUTN are list of bytes; for '2G' context, AUTN is not used
        returns a list containing the keys (list of bytes) computed in the USIM,
        on success:
            [RES, CK, IK (, Kc)] or [AUTS] for '3G'
            [RES] or [AUTS] for 'GBA'
            [RES, Kc] for '2G'
        or None on error
        '''
        # prepare input data for authentication
        if ctx in ('3G', 'VGCS', 'GBA', 'MBMS') and len(RAND) != 16 \
        and len(AUTN) != 16: 
            if self.dbg: 
                print '[WNG] authenticate: bad parameters'
            return None
        
        inp = []
        if ctx == '3G':
            P2 = 0x81
        elif ctx == 'VGCS':
            P2 = 0x82
            print '[+] Not implemented. Exit.'
            return None
        elif ctx == 'MBMS':
            print '[+] Not implemented. Exit.'
            return None
        elif ctx == 'GBA': 
            P2 = 0x84
            inp = [0xDD]
        inp.extend( [len(RAND)] + RAND + [len(AUTN)] + AUTN )
        if ctx not in ['3G', 'VGCS', 'MBMS', 'GBA']: 
        # and also, if ctx == '2G'... the safe way 
        # to avoid desynchronizing our USIM counter
            P2 = 0x80
            if len(RAND) != 16: 
                if self.dbg: 
                    print '[WNG] bad parameters'
                return None
            # override input value for 2G authent
            inp = [len(RAND)] + RAND

        self.coms.push( self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp) )
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push( self.GET_RESPONSE(Le=self.coms()[2][1]) )
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                if P2 == 0x80:
                    if self.dbg: 
                        print '[+] Successful 2G authentication. Get [RES, Kc]'
                    values = LV_parser(val)
                    # returned values are (RES, Kc)
                    return values
                # not adapted to 2G context with Kc, RES: to be confirmed...                
                if val[0] == 0xDB:
                    if P2 == 0x81 and self.dbg: 
                        print '[+] Successful 3G authentication. ' \
                              'Get [RES, CK, IK(, Kc)]' 
                    elif P2 == 0x84 and self.dbg: 
                        print '[+] Successful GBA authentication. Get [RES]'
                    values = LV_parser(val[1:])
                    # returned values can be (RES, CK, IK) or (RES, CK, IK, Kc)
                    return values
                elif val[0] == 0xDC:
                    if self.dbg: 
                        print '[+] Synchronization failure. Get [AUTS]'
                    values = LV_parser(val[1:])
                    return values
        elif self.dbg:
            print '[+] authentication error: %s' % self.coms()
            return None
        else:
            print "[ERR] invalid response"

    def get_ak(self, RAND, Ki):
        bin_rand = RAND.decode("hex")
        bin_ki = Ki.decode("hex")        
        ak = xor_strings(bin_rand, bin_ki).encode("hex")
        return ak