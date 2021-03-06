""" This module contains functions which are shared among many plugins """
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import pyflag.Registry as Registry
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import dissect
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework

def IP2str(ip):
    """ Returns a string representation of the 32 bit network order ip """
    tmp = list(struct.unpack('=BBBB',struct.pack('=L',ip)))
    tmp.reverse()
    return ".".join(["%s" % i for i in tmp])
                
class NetworkScanner(BaseScanner):
    """ This is the base class for network scanners.

    Note that network scanners operate on discrete packets, where stream scanners operate on whole streams (and derive from StreamScannerFactory).
    """
    def __init__(self,inode,ddfs,outer,factories=None,fd=None):
        BaseScanner.__init__(self,inode,ddfs,outer,factories=factories,fd=fd)
        try:
            self.fd.link_type
            self.ignore = False
        except:
            self.ignore = True
            
    def finish(self):
        """ Only allow scanners to operate on pcapfs inodes """
        try:
            if self.fd.link_type:
                return True
        except:
            return False
    
    def process(self,data,metadata=None):
        """ Pre-process the data for all other network scanners """
        try:
            ## We may only scan network related filesystems like
            ## pcapfs.
            link_type = self.fd.link_type
        except:
            return
        
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        self.packet_id = self.fd.tell()-1
        self.packet_offset = self.fd.packet_offset
        metadata['mime'] = "text/packet"
          
        try:
            self.proto_tree = metadata['proto_tree'][self.packet_id]
        except KeyError,e:
            ## Now dissect it.
            self.proto_tree = dissect.dissector(data, link_type,
                                  self.packet_id, self.packet_offset)

            ## Store it for the future
            metadata['proto_tree']={ self.packet_id: self.proto_tree }

class StreamTypeScan(ScanIfType):
    """ By Default we now rely on the Magic to idenitify the stream.

    For those streams which rely on port numbers (should not be
    used really), you can leave the default types (it will match
    anything - but we will only call process_stream on streams).
    """
    types = [ "." ]

    def finish(self):            
        ## Call the base classes process_stream method with the
        ## given stream.
        if not self.boring_status:
            try:
                self.fd.reverse
            except AttributeError,e:
                return

            self.outer.process_stream(self.fd, self.factories)

class StreamScannerFactory(GenScanFactory):
    """ This is a scanner factory which allows scanners to only
    operate on streams.
    """
    order = 2
    depends = ['TypeScan']
    group = 'NetworkScanners'

    def stream_to_server(self, stream, protocol):
        if stream.dest_port in dissect.fix_ports(protocol):
            forward_stream = stream.inode_id
            reverse_stream = stream.reverse
        else:
            return None, None

        return forward_stream, reverse_stream

    def process_stream(self, stream, factories):
        """ Stream scanners need to over ride this to process each stream """
        pass
    
    def scan_as_file(self, inode, factories):
        """ Scans inode as a file (i.e. without any Stream scanners). """
        fd = self.fsfd.open(inode=inode)
        ## If does not matter if we use stream scanners on files
        ## because they would ignore it anyway.
        #factories = [ x for x in factories if not isinstance(x, StreamScannerFactory) ]

        Scanner.scanfile(self.fsfd,fd,factories)
        fd.close()

    class Scan(StreamTypeScan):
        pass
