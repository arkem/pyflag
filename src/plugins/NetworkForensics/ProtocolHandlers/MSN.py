""" This module implements processing for MSN Instant messager traffic

Most of the information for this protocol was taken from:
http://www.hypothetic.org/docs/msn/ietf_draft.txt
http://www.hypothetic.org/docs/msn/client/file_transfer.php
http://www.hypothetic.org/docs/msn/notification/authentication.php

"""
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.logging as logging
import base64
import plugins.NetworkForensics.PCAPFS as PCAPFS

def safe_base64_decode(s):
    """ This attempts to decode the string s, even if it has incorrect padding """
    tmp = s
    for i in range(1,5):
        try:
            return base64.decodestring(tmp)
        except:
            tmp=tmp[:-i]
            continue

    return s

allowed_file_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_ "

def get_temp_path(case,inode):
    """ Returns the full path to a temporary file based on filename.
    """
    filename = inode.replace('/','-')
    result= "%s/case_%s/%s" % (config.RESULTDIR,case,filename)
    return result

class message:
    """ A class representing the message """
    def __init__(self,dbh,fd,ddfs):
        self.dbh=dbh
        self.fd=fd
        self.ddfs = ddfs
        self.client_id='Unknown'
        self.session_id = -1
        self.inodes = []
        self.participants = []

    def get_packet_id(self):
        self.offset = self.fd.tell()
        ## Try to find the time stamp of this request:
        #####This doesn't return the correct result at present, close but no cigar.
        self.packet_id = self.fd.get_packet_id(self.offset)
        #print "self.packet_id: %s" % self.packet_id
        return self.packet_id

    def add_participant(self,username):
        #Not sure I really need to check for uniqueness here, but seems sensible
        try:
            if (self.participants.index(username)):
                #Already in the list
                pass
        except ValueError:
            #Don't have this one, so insert it
            self.participants.append(username)
            print "Appending to participants:%s" % (self.participants)

    def del_participant(self,username):
        try:
            print "Removing participant:%s" % username
            self.participants.remove(username)
        except:
            #name wasn't in participants for some reason, shouldn't really happen.
            pass

        
    def parse(self):

        """ We parse the first message from the file like object in
        fp, thereby consuming it"""
        
        # Read the first command:
        self.cmdline=self.fd.readline()
        if len(self.cmdline)==0: raise IOError("Unable to read command from stream")

        try:
            ## We take the last 3 letters of the line as the
            ## command. If we lose sync at some point, readline will
            ## resync up to the next command automatically
            self.cmd = self.cmdline.split()[0][-3:]

            ## All commands are in upper case - if they are not we
            ## must have lost sync:
            if self.cmd != self.cmd.upper() or not self.cmd.isalpha(): return None
        except IndexError:
            return ''
        
        ## Dispatch the command handler
        try:
            return getattr(self,self.cmd)()
        except AttributeError,e:
            logging.log(logging.VERBOSE_DEBUG,"Unable to handle command %r from line %s (%s)" % (self.cmd,self.cmdline,e))
            return None

    def get_data(self):
        return self.data

    def parse_mime(self):
        """ Parse the contents of the headers

        """
        words = self.cmdline.split()
        self.length = int(words[-1])
        self.offset = self.fd.tell()
        self.headers = {}
        ## Read the headers:
        while 1:
            line = self.fd.readline()
            if line =='\r\n': break
            try:
                header,value = line.split(":")
                self.headers[header.lower()]=value.lower().strip()
            except ValueError:
                print "Parse mime failed on:%s" % line
                pass

        current_position = self.fd.tell()
        self.data = self.fd.read(self.length-(current_position-self.offset))
    
    def CAL(self):

        """ Target is inviting someone to a new session

        CAL 8 dave@passport.com\r\n

        Server responds, saying I am ringing the person:

        We use this to store the current session ID for the entire TCP stream.
        
        CAL 8 RINGING 17342299\r\n

        """
        words = self.cmdline.split()
        if (words[2] == "RINGING"):
            self.session_id=words[3]
        else:
            self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r, type=%r, sender=%r",(self.fd.inode,self.get_packet_id(),self.session_id, words[2],"INVITE","%s (Target)" % self.client_id))
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,words[2],'user_msn_passport',words[2]))
            
	self.state = "CAL"

    def OUT(self):
        """Target left MSN session"""
        
        words = self.cmdline.split()
        self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r, type=%r, sender=%r",(self.fd.inode,self.get_packet_id(),self.session_id,'SWITCHBOARD SERVER',"TARGET LEFT SESSION","%s (Target)" % self.client_id))
        
    def BYE(self):
        """A participant has left the session

        e.g.

        BYE blah@hotmail.com

        """
        
        words = self.cmdline.split()
        self.del_participant(words[1])
        self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r, type=%r, sender=%r",(self.fd.inode,self.get_packet_id(),self.session_id,'SWITCHBOARD SERVER',"USER LEFT SESSION",words[1]))
        

    def USR(self):
        """
        Target logging into switchboard server using same auth string as passed back by server in XFR

        Most of this info is pretty boring.  I only store stuff that has usernames in it.
        
                
        USR <transation id> example@passport.com 17262740.1050826919.32307

        If successful, server passes back (currently ignoring):
        
        USR <same transaction id> OK example@passport.com Example%20Name


        Initial USR

        Initiates authentication process.

        USR trid TWN I account_name

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN")
            * I : Status of authentication (always "I" for initial)
            * account_name : Your passport address 

        Returns
        The server will either respond with XFR to transfer you, or with USR to continue the authentication process.

        Subsequent USR Response:

        USR trid TWN S auth_string

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN")
            * S : Status of authentication (always "S" for subsequent)
            * auth_string : String used for Tweener authentication 


        [edit]
        Final USR

        USR trid TWN S ticket

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN" for Tweener)
            * S : Status of authentication (always "S" for subsequent)
            * ticket : Ticket retrieved after Tweener authentication 

        Returns

        USR trid OK account_name display_name verified 0

            * trid : Transaction ID
            * OK : Confirms a successful login
            * account_name : Your Passport account-name
            * display_name : Your URL Encoded friendly-name
            * verified : Either 0 or 1 if your account is verified
            * 0 : Unknown (Kids passport?) 
        
	"""
	words = self.cmdline.split()
        
        print "USR:%s" % self.cmdline.strip()
        self.state = "USR"
        
        
        if (words[2]=="OK"):
            
            self.client_id = words[3]
            self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, recipient=%r,type=%r,sender=%r,transaction_id=%r,session_id=%r",(self.fd.inode,self.get_packet_id(),"SWITCHBOARD SERVER","TARGET ENTERING NEW SWITCHBOARD SESSION","%s (Target)" % self.client_id,words[1],self.session_id))

            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'target_msn_passport',words[3]))
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'url_enc_display_name',words[4]))
            
        elif (words[2]=="TWN")and(words[3]=="I"):
            self.client_id = words[4]
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'target_msn_passport',words[4]))
            
        else:
            #must be of form: USR <transation id> example@passport.com 17262740.1050826919.32307
            self.client_id = words[2]
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'target_msn_passport',words[2]))
            
        

    def XFR(self):

        #I don't think this information is userful enough to record,
        #it is really just noise.  We already know the IPs from the
        #stream data, so not really necessary or useful to record them
        #here.
        self.state = "XFR"
        pass
        
##        """This command creates a new switchboard session.

##        Request:
##        XFR <transaction id> SB

##        e.g.
##        XFR 15 SB

##        Response:
##        XFR <same transaction id> SB <ip of switchboard server:port> <auth type, always=CKI> <auth string to prove identity>

##        e.g.
##        XFR 15 SB 207.46.108.37:1863 CKI 17262740.1050826919.32308

##        OR you can be transferred to a different nameserver:

##        XFR trid NS address 0 current_address

##        * trid : Transaction ID
##        * NS : Tells you that you are being redirected to a notification server
##        * address : IP and port of server you are being redirected to (separated by a colon)
##        * 0 : unknown
##        * current_address : The address of the dispatch/notification server you are currently connected to

##        """

##        words = self.cmdline.split()
##        print "XFR:%s" % self.cmdline.strip()
##        try:
##            self.switchboard_ip = words[3].split(":")[0]
##            self.switchboard_port = words[3].split(":")[1]
##            #This is a server response
##            self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, recipient=%r,type=%r,sender=%r,transaction_id=%r,auth_string=%r,sb_server_ip=%r",(self.fd.inode,self.get_packet_id(),"%s (Target)" % self.client_id,"SWITCHBOARD SERVER OFFER","NOTIFICATION SERVER",words[1],words[5],self.switchboard_ip))
##        except:
##            pass
##            #This is a client request, I don't think it is interesting enough to record.
##            #self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, recipient=%r,type=%r,sender=%r,transaction_id=%r",(self.fd.inode,self.get_packet_id(),"NOTIFICATION SERVER","NEW SWITCHBOARD SESSION REQUEST","%s (Target)" % self.client_id,words[1]))
##        
            
		
    def ANS(self):
        """ Logs into the Switchboard session.

        We use this to store the current session ID and client_id (target username) for this entire TCP stream.

        ANS <transaction id> <account name> <auth string> <session id>
        
        e.g.
        ANS 1 name_123@hotmail.com 849102291.520491113 11752013

        Ignore these responses from the server:
        ANS 1854 OK
        
        """
        words = self.cmdline.split()

        if (words[2].find("OK")<0):

            try:
                self.session_id=int(words[-1])
                ## This stores the current clients username
                self.client_id = words[2]
                self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r,transaction_id=%r, session_id=%r, recipient=%r,type=%r,sender=%r",
                                 (self.fd.inode,self.get_packet_id(),words[1],self.session_id,"SWITCHBOARD SERVER","TARGET JOINING_SESSION","%s (Target)" % self.client_id))

                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'target_msn_passport',words[2]))

            except Exception,e:
                print "ANS not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass

            self.state = "ANS"
	
    def IRO(self):
        """
        List of current participants.

        IRO <transaction id> <number of this IRO> <total number of IRO that will be sent> <username> <display name>
        
        """
        words = self.cmdline.split()
        try:
            self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r,transaction_id=%r, session_id=%r, recipient=%r,type=%r,sender=%r",
                             (self.fd.inode,self.get_packet_id(),words[1],self.session_id, words[4],"CURRENT_PARTICIPANTS",words[4]))
            self.state = "IRO"

            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,words[4],'user_msn_passport',words[4]))
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,words[4],'url_enc_display_name',words[5]))

            self.add_participant(words[4])                

        except Exception,e:
                print "IRO not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass

    def RNG(self):
        """ Target is being invited to a new session

        We use this to store the current session ID for this entire TCP stream.

        Format:
        RNG <sessionid> <switchboard server ip:port> <auth type, always=cki> <auth string> <nick of inviter> <url encoded display name of inviter>
        """
        words = self.cmdline.split()
        self.session_id = words[1]

        #The inviter is a participant
        self.add_participant(words[5])
        self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r, type=%r, sender=%r",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,"TARGET INVITED",words[5]))
	self.state = "RNG"

        self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,words[5],'user_msn_passport',words[5]))

        self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,words[5],'url_enc_display_name',words[6]))
        
    def JOI(self):
        """ Sent to all participants when a new client joins

        JOI bob@passport.com Bob
        
        """
        words = self.cmdline.split()
        self.add_participant(words[1])
        self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r,type=%r,sender=%r",
                          (self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,"USER JOINING_SESSION WITH TARGET",words[1]))

        self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,words[1],'user_msn_passport',words[1]))
        self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,words[1],'url_enc_display_name',words[2]))
        
	self.state = "JOI"

    def CVR(self):
        """Version information, including OS information

        From the client:
        CVR <transaction id> <locale ID in hex> <os type> <os ver> <arch> <client name> <client version> <always MSMSGS> <msn passport>

        >>> CVR 2 0x0409 win 4.10 i386 MSNMSGR 5.0.0544 MSMSGS example@passport.com\r\n

        From the server:

        CVR <transaction id> <recommended verion> <same again> <minimum version required> <download url> <more info url>
        
        <<< CVR 2 6.0.0602 6.0.0602 1.0.0000 http://download.microsoft.com/download/8/a/4/8a42bcae-f533-4468-b871-d2bc8dd32e9e/SETUP9x.EXE http://messenger.msn.com\r\n

        """
        words = self.cmdline.split()

        # I think we only care about the client, not the server, hence:
        if (words[2].find("x")==1):
            self.client_id=words[9]
            try:
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'locale',words[2]))
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'os'," ".join(words[3:6])))
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'client'," ".join(words[6:8])))
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,transaction_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),words[1],self.session_id,"%s (Target)" % self.client_id,'target_msn_passport',words[9]))
                
                self.state = "CVR"

            except Exception,e:
                print "CVR not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass

    def PRP(self):
        """Phone numbers.

        Valid Types:
        
        # PHH - home phone number
        # PHW - work phone number
        # PHM - mobile phone number
        # MOB - are other people authorised to contact me on my MSN Mobile (http://mobile.msn.com/) device?
        # MBE - do I have a mobile device enabled on MSN Mobile (http://mobile.msn.com/)?
        
        Phone numbers are not sent if they are empty, MOB and MBE
        aren't sent unless they are enabled. Because of this, the only
        way to tell whether you've finished receiving PRPs is when you
        receive the first LSG response (there will always be at least
        one LSG response).

        The value for the first three items can be anything up to 95
        characters. This value can contain any characters allowed in a
        nickname and is URL Encoded.

        The value of MOB and MBE can only be Y (yes). If MOB is set,
        the client has allowed other people to contact him on his
        mobile device through the PAG command. If MBE is set, that
        shows that the client has enabled a mobile device on MSN
        Mobile (http://mobile.msn.com/). Note that these values are
        completely independent from the PHM mobile device number.
        

        e.g.
        PRP PHH 555%20555-0690

        """
        words = self.cmdline.split()

        print "PRP: %s" % self.cmdline
        
        
        try:
            if (words[1]=="PHH"):
                
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'home_phone',words[2]))
                
            elif (words[1]=="PHW"):
                
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'work_phone',words[2]))
                
            elif (words[1]=="PHM"):
                
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'mobile_phone',words[2]))
                
            elif (words[1]=="MOB"):
                
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'msn_mobile_auth',words[2]))
                
            elif (words[1]=="MBE"):
                
                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'msn_mobile_device',words[2]))
                
            else:

                print "PRP not decoded correctly: %s" % self.cmdline.strip()

        except Exception,e:
                print "PRP not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass
            
        self.state = "PRP"    
    

    def LSG(self):
        """Contact groups.  Sent by the server when target logs on.

        LSG 0 Other%20Contacts 0\r\n
        LSG 1 Coworkers 0\r\n
        LSG 2 Friends 0\r\n
        LSG 3 Family 0\r\n

        """
        words = self.cmdline.split()

        print "LSG: %s" % self.cmdline
        
        try:
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'contact_list_groups',words[1:2]))

        except Exception,e:
                print "LSG not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass
            
        self.state = "LSG"

    def LST(self):
        """Contact list members.  Sent by the server when target logs on.

        LST principal1@passport.com principal1 4\r\n
        LST principal2@passport.com principal2 10\r\n
        LST principal3@passport.com principal3 11 1,3\r\n
        LST principal4@passport.com principal4 11 0\r\n

        # The first parameter is the account name.
        # The second parameter is the nickname. (For more information on nicknames, see the Names page)
        # The third parameter is a number representing the lists the person is in (discussed below)
        # If the person is in your FL, the fourth parameter is a comma-separated list of group numbers they belong to

        Each list has a numerical value:

        A principal's list number represents the sum of the lists the
        principal is in. For example, someone on your forward and
        allow lists but not your block or reverse lists would have a
        list number of 3.

        """
        words = self.cmdline.split()

        list_lookup={}
        list_lookup['forward_list']=1
        list_lookup['allow_list']=2
        list_lookup['block_list']=4
        list_lookup['reverse_list']=8
        list_lookup['pending_list']=16
        
        print "LST: %s" % self.cmdline

        listresults=[]
        for listtypes in list_lookup.keys():
            if ((list_lookup[listtypes] & words[3])>0):
                listresults.append(listtypes)
        print listresults
        
        try:
            self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'contact_list_member',"account name:%s. nickname:%s. in lists:%s. in groups:%s"%(words[1],words[2],listresults,words[4])))

        except Exception,e:
                print "LST not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
                pass
            
        self.state = "LST"

    #Ignore these commands
    def ACK (self):
        pass
    def PNG (self):
        #Client ping
        pass
    def QNG (self):
        #Server ping reply
        pass
    def VER (self):
        #see below
        pass
# This is not useful. The CVR command provides much better information.
##    def VER(self):
##        """ Version information

##        Not really any way to tell whether this is server->client or client->server.

##        e.g.
        
##        < VER 1 MSNP9 MSNP10 MSNP11 MSNP12 CVR0\r\n
##        > VER 1 MSNP12 MSNP11 MSNP10 MSNP9 CVR0\r\n

##        """
##        words = self.cmdline.split()
##	print "VER command: %s" % self.cmdline
        
##	try:
##            self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r,transaction_id=%r, recipient=%r,type=%r,sender=%r",
##                             (self.fd.inode,self.get_packet_id(),words[1],"SERVER/Target","VERSION="+words[2:],"SERVER/Target"))
##            ## This stores the current clients username
##        except: pass
##	self.state = "VER"



##    def ADD(self):
##        """Adding people to your lists.

##        Forward List (FL)
        
##        The forward list, abbreviated as FL, is the list of principals
##        whose presence you are subscribed to. You can expect to be
##        notified about their on-line state, phone numbers, etc. This
##        is what a layman would call their contact list.

##        Everyone in your forward list belongs to one or more groups,
##        identified by their group number. By default, they belong to
##        group 0.

##        Reverse List (RL)
        
##        The reverse list, abbreviated as RL, is the list of principals
##        that have you on their forward list. You cannot make
##        modifications to it. If you attempt to add or remove people
##        from this list, you will be immediately disconnected from the
##        NS with no error message.  [edit]

##        Allow List (AL)
        
##        The allow list, abbreviated as AL, is the list of principals
##        that you allow to see your online presence - as opposed to
##        your reverse list, which is the list of people who request to
##        see your online presence. If someone removes you from his or
##        her contact list, he or she is automatically removed from your
##        RL but not your AL. He or she no longer receives online
##        presence from you, but if he or she adds you again, your
##        client can act in the knowledge that you previously allowed
##        him or her to see your presence.

##        Block List (BL)

##        The block list, abbreviated as BL, is the list
##        of people that are blocked from seeing your online
##        presence. They will never receive your status, and when they
##        try to invite you to a switchboard session, they will be
##        notified that you are offline. No-one can be on the AL and the
##        BL at the same time, and if you try to add someone to both
##        lists, you will receive error 219.

##        # The first parameter is the list you want to add the
##        # principal to.
        
##        # The second parameter is the principal's account name.

##        # The third parameter is a nickname you assign to the
##        # principal. The official client always uses the principal's
##        # account name as the nickname, and that is why when you add a
##        # principal, his or her name always shows as his or her
##        # account name until he or she logs on and you receive an
##        # updated display name.

##        # If you are adding a principal to your FL, there may be a
##        # fourth parameter specifying the group ID that you are adding
##        # the principal to. If you do not specify a group ID, zero is
##        # implied. You may add the same principal to your FL later
##        # specifying another group to have the principal in multiple
##        # groups.

##        e.g.
##        ADD 20 AL example@passport.com example@passport.com

##        """
##        words = self.cmdline.split()

##        print "ADD: %s" % self.cmdline
        
##        try:
##            if (words[2]=="AL"):

##                self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r, type=%r, sender=%r,sb_server_ip=%r,auth_string=%r",(self.fd.inode,self.get_packet_id(),words[1], "(Target)","INVITE",words[5],words[1].split(":")[0],words[4]))
                
##                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'home_phone',words[2]))
                
##            elif (words[1]=="PHW"):
                
##                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'work_phone',words[2]))
                
##            elif (words[1]=="PHM"):
                
##                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'mobile_phone',words[2]))
                
##            elif (words[1]=="MOB"):
                
##                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'msn_mobile_auth',words[2]))
                
##            elif (words[1]=="MBE"):
                
##                self.dbh.execute("""insert into msn_users set inode=%r,packet_id=%r,session_id=%r,nick=%r,user_data_type=%r,user_data=%r""",(self.fd.inode,self.get_packet_id(),self.session_id,"%s (Target)" % self.client_id,'msn_mobile_device',words[2]))
                
##            else:

##                print "ADD not decoded correctly: %s" % self.cmdline.strip()

##        except Exception,e:
##                print "ADD not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e)
##                pass
            
##        self.state = "ADD"
                         
    def plain_handler(self,content_type,sender,friendly_sender,is_server):
        """ A handler for content type text/plain """

        self.dbh.execute(""" insert into msn_session set sender=%r,friendly_name=%r,
        recipient=%r, inode=%r, packet_id=%r, data=%r, session_id=%r, type=%r
        """,(
            sender,friendly_sender, self.recipient, self.fd.inode, self.get_packet_id(),
            self.get_data(), self.session_id,'MESSAGE'
            ))

    def control_msg_handler(self,content_type,sender,friendly_sender,is_server):
        """ A handler for content type text/x-msmsgscontrol

        If this is the client sending a message out:

        This gives us another chance to set self.client_id
        (i.e. target username) for the stream, using the Typing User
        messages.  This means that if we miss the ANS, we can still
        identify who 'Target' is.

        If this is the server sending a message in:

        This gives us another chance to find out the participating
        users in the session.  This means if we miss one or all of the
        IRO statements, we still know who is in the session
        
        """
        if is_server:
            #Typing user message from server - way to identify participants!
            self.add_participant(self.headers['typinguser'])
        else:
            self.client_id = self.headers['typinguser']

    def profile_msg_handler(self,content_type,sender,friendly_sender,is_server):
        """ A handler for content type text/x-msmsgsprofile

        These messages can potentially contain great info (providing
        the user has set the settings in the client)
        
        """
        ####Don't need this, just handle SBS as in S50.  Or maybe just make special case of MSG Hotmail
        #self.client_id = self.headers['typinguser']
        #print "The Typing User is: %s" % (self.client_id)

    def ignore_type(self,content_type,sender,friendly_sender,is_server):
        #Nonexistent callback for ignored types.
        print "Ignoring message:%s.  Headers:%s. Data:%s" % (self.cmdline.strip(),self.headers,self.data.strip())

    def p2p_handler(self,content_type,sender,friendly_sender,is_server):
        """ Handle a p2p transfer """

        def strip_username(p2pusername):
            # TO and FROM are of format <msnmsgr:name@hotmail.com> so strip the extra stuff out
            return p2pusername.replace('<msnmsgr:','').strip('>')
            
            
        data = self.get_data()
        ## Now we break out the header:
        ( channel_sid, id, offset, total_data_size, message_size ) = struct.unpack(
            "IIQQI",data[:4+4+8+8+4])

        ## MSN header is 48 bytes long
        data = data[48:48+message_size]
        
        ## When channel session id is 0 we are negotiating a transfer
        ## channel
        if channel_sid==0:
            fd = cStringIO.StringIO(data)
            request_type=fd.readline()
            if request_type.startswith("INVITE"):
                ## We parse out the invite headers here:
                headers = {}
                while 1:
                    line = fd.readline()
                    if not line: break
                    tmp = line.find(":")
                    key,value = line[:tmp],line[tmp+1:]
                    headers[key.lower()]=value.strip()

                context = safe_base64_decode(headers['context'])

                self.dbh.execute("insert into msn_p2p set session_id = %r, channel_id = %r, to_user= %r, from_user= %r, context=%r",
                                 (self.session_id,headers['sessionid'],
                                  headers['to'],headers['from'],context))
                
                self.dbh.execute("insert into msn_session set inode=%r, packet_id=%r, session_id=%r, recipient=%r,type=%r,sender=%r,data=%r",
                          (self.fd.inode,self.get_packet_id(),self.session_id,strip_username(headers['to']),"P2P FILE TRANSFER",strip_username(headers['from']),"p2p session id:%s" % headers['sessionid']))

                ## Add a VFS entry for this file:
                new_inode = "CMSN%s-%s" % (headers['sessionid'],
                                           self.session_id)
                try:
                ## Parse the context line:
                    parser = ContextParser()
                    parser.feed(context)
                    filename = parser.context_meta_data['location']
                    size=parser.context_meta_data['size']
                    if len(filename)<1: raise IOError
                except:
                    ## If the context line is not a valid xml line, we
                    ## just make a filename off its printables.
                    filename = ''.join([ a for a in context if a in allowed_file_chars ])
                    size=0

                try:
                    mtime = self.fd.ts_sec
                except:
                    mtime = 0
                
                ## The filename and size is given in the context
                self.ddfs.VFSCreate(self.fd.inode, new_inode, "MSN/%s" %
                                    (filename) , mtime=mtime,
                                    size=size)

                self.inodes.append(new_inode)
                
        ## We have a real channel id so this is an actual file:
        else:
            filename = get_temp_path(self.dbh.case,"%s|CMSN%s-%s" % (self.fd.inode, channel_sid,self.session_id))
            fd=os.open(filename,os.O_RDWR | os.O_CREAT)
            os.lseek(fd,offset,0)
            bytes = os.write(fd,data)
            if bytes <message_size:
                logging.log(logging.WARNINGS,  "Unable to write as much data as needed into MSN p2p file. Needed %s, write %d." %(message_size,bytes))
            os.close(fd)
            
    ct_dispatcher = {
        #Ignore list:
        #text/x-msmsgscontrol are 'typing user' messages.
        
        'text/plain': plain_handler,
        'application/x-msnmsgrp2p': p2p_handler,
        'text/x-msmsgscontrol': control_msg_handler,
        'text/x-msmsgsprofile': profile_msg_handler
        }
            
    def MSG(self):
        """ Sends message to members of the current session

        There are two types of messages that may be sent:
        1) A message from the client to the message server. This does not contain the nick of the client, but does contain a transaction ID.  This message is sent to all users in the current session.
        2) A message from the Switchboard server to the client contains the nick of the sender.

        These two commands are totally different.

        1.

        MSG 1532 U 92
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user@hotmail.com

        Format is: MSG <Transaction ID> <Type of ACK required> <length of message in bytes>

        Transaction ID is used to correlate server responses to client requests.

        2.

        MSG user2@hotmail.com I%20am%20so%20great 102
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user2@hotmail.com

        Format is: MSG <Nick> <URL encoded displayname> <length of message in bytes>

        The profile messages look like this:
        
        SBS 0 null
        MSG Hotmail Hotmail 999
        MIME-Version: 1.0
        Content-Type: text/x-msmsgsprofile; charset=UTF-8
        LoginTime: 1130000813
        EmailEnabled: 1
        MemberIdHigh: 98989
        MemberIdLow: 9898989898
        lang_preference: 1033
        preferredEmail:
        country: AU
        PostalCode:
        Gender:
        Kid: 0
        Age:
        BDayPre:
        Birthday:
        Wallet:
        Flags: 1073759303
        sid: 500
        kv: 7
        MSPAuth: 78vuxsrLuGBgVaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatdYDSaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$$
        ClientIP: 60.0.0.1
        ClientPort: 39620
        ABCHMigrated: 1
        
        """
        ## Read the data for this MSG:
        self.parse_mime()
        words = self.cmdline.split()
        try:
            ## If the second word is a transaction id (int) its a message from client to server.  ie. FROM target to all users in session.
            tid = int(words[1])
            sender = "%s (Target)" % self.client_id
            friendly_sender = "Implied Client Machine"
            print "participants:%s" % (",".join(self.participants))
	    self.recipient = ",".join(self.participants)
            server = False
        except ValueError:
            # Message TO target
            tid = 0
            sender = words[1]
            friendly_sender = words[2]
            server = True
	    self.recipient = "%s (Target)" % self.client_id
        try:
            content_type = self.headers['content-type']
        except:
            content_type = "unknown/unknown"
            logging.log(logging.VERBOSE_DEBUG,"Couldn't figure out MIME type for this message: %s" % self.cmdline)

        ## Now dispatch the relevant handler according to the content
        ## type:
        try:
            ct = content_type.split(';')[0]
            self.ct_dispatcher[ct](self,content_type,sender,friendly_sender,server)
        except KeyError,e:
            logging.log(logging.VERBOSE_DEBUG, "Unable to handle content-type %s(%s) - ignoring message %s " % (content_type,e,tid))
        self.state = "MSG"
	
from HTMLParser import HTMLParser

class ContextParser(HTMLParser):
    """ This is a simple parser to parse the MSN Context line """
    def handle_starttag(self, tag, attrs):
        self.context_meta_data = FlagFramework.query_type(attrs)

class MSNScanner(StreamScannerFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True

    def __init__(self,fsfd):
        StreamScannerFactory.__init__(self,fsfd)
        self.processed=[]

    def prepare(self):

        self.dbh.execute(
            """ CREATE TABLE if not exists `msn_session` (
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT NOT NULL,
            `session_id` INT,
            `sender` VARCHAR(250),
            `recipient` VARCHAR( 250 ),
            `friendly_name` VARCHAR( 255 ) NOT NULL ,
            `type` VARCHAR(50),
            `data` TEXT NOT NULL,
            `transaction_id`  INT
            )""")
        self.dbh.execute(
            """ CREATE TABLE if not exists `msn_p2p` (
            `inode` VARCHAR(250),
            `session_id` INT,
            `channel_id`  INT,
            `to_user` VARCHAR(250),
            `from_user` VARCHAR(250),
            `context` TEXT
            )""")
        self.dbh.execute(
            """ CREATE TABLE if not exists `msn_users` (
            `inode` VARCHAR(50) NOT NULL,
            `packet_id`  INT NOT NULL,
            `session_id` INT,
            `transaction_id`  INT,
            `nick` VARCHAR(50) NOT NULL,
            `user_data_type` enum('msn_passport','display_name','url_enc_display_name','locale','os','client') default NULL ,
            `user_data` TEXT NOT NULL
            )""")
        self.msn_connections = {}
        #self.user_data={}

    def process_stream(self, stream, factories):
        ports = dissect.fix_ports("MSN")
        
        if stream.src_port in ports or stream.dest_port in ports:
            try:
                #Keep track of the streams we have combined so we don't process reverse again
                #self.processed is a ring buffer so it doesn't get too big
                if self.processed.index(stream.con_id):
                    #Already processed
                    pass
            except ValueError:

                #This returns the forward and reverse stream associated with the MSN port (uses port numbers in .pyflagrc).
                forward_stream, reverse_stream = self.stream_to_server(stream, "MSN")

                #We need both streams otherwise this won't work
                if not reverse_stream or not forward_stream: return

                logging.log(logging.VERBOSE_DEBUG,"Opening Combined Stream S%s/%s for MSN" % (forward_stream, reverse_stream))

                #Create the combined inode
                combined_inode = "I%s|S%s/%s" % (stream.fd.name, forward_stream, reverse_stream)

                # Open the combined stream.
                fd = self.fsfd.open(inode=combined_inode)
                
                m=message(self.dbh, fd, self.fsfd)
                while 1:
                    try:
                        result=m.parse()
                    except IOError:

                        break

                for inode in m.inodes:
                    self.scan_as_file("%s|%s" % (stream.inode, inode), factories)

                print "Appending ids: %s, %s" % (forward_stream,reverse_stream)
                self.processed.append([forward_stream,reverse_stream])
                
class MSNFile(File):
    """ VFS driver for reading the cached MSN files """
    specifier = 'C'
        
class BrowseMSNSessions(Reports.report):
    """ This allows MSN sessions to be browsed.

    Note that to the left of each column there is an icon with an
    arrow pointing downwards. Clicking on this icon shows the full msn
    messages for all sessions from 60 seconds prior to this message.

    This is useful if you have isolated a specific message by
    searching for it, but want to see what messages were sent around
    the same time to get some context.
    """
    name = "Browse MSN Sessions"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
        except KeyError:
            pass

    def display(self,query,result):
        """ This callback renders an icon which when clicked shows the
        full msn messages for all sessions from 60 seconds prior to
        this message."""
        
        result.heading("MSN Chat sessions")

        def draw_prox_cb(value):
            tmp = result.__class__(result)
            tmp.link('Go To Approximate Time',
              target=FlagFramework.query_type((),
                family=query['family'], report=query['report'],
                where_Prox = ">%s" % (int(value)-60),
                case = query['case'],
              ),
              icon = "stock_down-with-subpoints.png",
	                     )

            return tmp

        result.table(
            #TODO find a nice way to separate date and time (for exporting csv separate), but not have it as the default...
            #date: 'from_unixtime(pcap.ts_sec,"%Y-%m-%d")'
            #time: 'concat(from_unixtime(pcap.ts_sec,"%H:%i:%s"),".",pcap.ts_usec)'
            
            columns = ['pcap.ts_sec', 'concat(from_unixtime(pcap.ts_sec),".",pcap.ts_usec)', 'inode', 'concat(left(inode,instr(inode,"|")),"p0|o",cast(packet_id as char))', 'session_id','type','sender','recipient','data','transaction_id'],
            names = ['Prox','Timestamp','Stream', 'Packet', 'Session ID', 'Type','Sender','Recipient','Text','Transaction ID'],
            table = "msn_session join pcap on packet_id=id",
            callbacks = {'Prox':draw_prox_cb},
            links = [
	    	     None,None,
		     FlagFramework.query_type((),
                                              family="Disk Forensics", case=query['case'],
                                              report='View File Contents', 
                                              __target__='inode', mode="Combined streams"),
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='View Packet', 
                                              __target__='inode'),
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='BrowseMSNSessions', 
                                              __target__='where_Session ID'),
                     ],
            case = query['case'],
            hide_columns = ['Date']
            )

class BrowseMSNUsers(BrowseMSNSessions):
    """ This shows MSN participants (users). """
    name = "Browse MSN Users"
    family = "Network Forensics"
    #hidden = True
    def display(self,query,result):
        result.heading("MSN User Information Captured")
        result.table(
            columns = ['inode', 'concat(left(inode,instr(inode,"|")),"p0|o",cast(packet_id as char))','concat(from_unixtime(pcap.ts_sec),".",pcap.ts_usec)','user_data_type','nick','user_data','transaction_id','session_id'],
            names = ['Stream','Packet','Timestamp','Data Type','Nick','User Data','Transaction ID','Session ID'],
            table = "msn_users join pcap on packet_id=id",
            links = [FlagFramework.query_type((),
                                              family="Disk Forensics", case=query['case'],
                                              report='View File Contents', 
                                              __target__='inode', mode="Combined streams"),
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='View Packet', 
                                              __target__='inode'),
                     None,None,None,None,None,None
                     ],
            case = query['case']
            )

if __name__ == "__main__":
    fd = open("/tmp/case_demo/S93-94")
    data = fd.read()
    parse_msg(data)
