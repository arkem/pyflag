# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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

""" This is a module to parse SSL Traffic using keys retrieved from UDP packets. """

import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct
import binascii
from pyflag.ColumnTypes import StringType, PacketType, IPType
import pyflag.conf
config=pyflag.conf.ConfObject()
from plugins.NetworkForensics.NetworkScanner import StreamScannerFactory
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType, guess_date, PCAPTime, IPType, BlobType
import pyflag.Reports as Reports
from pyflag.FileSystem import File
import Crypto.Cipher.DES3 as DES3
import Crypto.Cipher.ARC4 as RC4

config.add_option("SSL_PORTS", default='[443,]',
                  help="A list of ports to be considered for SSL transactions")

# These methods are used for reading SSL/TLS records.
# SSLv2 is not properly supported. In practice, there is typically only ever
# one initial SSLv2 record (initial packet from client to server), the client
# typically indicates compatibility with SSLv3/TLS and all further packets from
# both sides are SSLv3/TLS. The first packet doesnt have anything we need.
# SSL basically looks like this:
# 1. C -> S Client Hello (indicate supported ciphers)
# 2. C <- S Server Hello (this is where chosen cipher is specified)
# 3. C <- S Server Certificate
#    ...? (could there be more here?
# 4. C <- S ServerHelloDone
# 5. C -> S ClientKeyExchange (this is where the keys are setup, 
#             we cant see it cos we dont have the servers priv key)
# 6. C -> S ChangeCipherSpec
# 7. C -> S Handshake Finished (encrypted)
# 8. C <- S ChangeCipherSpec
# 9. C <- S Handshake Finished (encrypted)
# ... Application Data ...
#
# The goal is to understand just enough of the protocol to identify 
# the symetric cipher used and find the start of the encrypted data
# We can then use the captured keys to attempt decryption

def read_chunk(fd):
    b = ord(fd.read(1))
    if(b & 0x80):   # SSLv2
        length = (b & 0x7f) << 8 | ord(fd.read(1))
        type = 0
        version = 2
    else:           # SSLv3/TLS
        format = "!HH"
        type = b
        version, length = struct.unpack(format, fd.read(struct.calcsize(format)))

    data = fd.read(length)
    return type, data, length

def parse_handshake(data, length):
    # skip type(1), len(3), version(2), random(32)
    session_id_len = struct.unpack("B", data[38])[0]
    # skip session_id (session_id_len, typically 32)
    cipher_code = struct.unpack("!H", data[38+1+session_id_len:38+1+session_id_len+2])[0]
    if cipher_code == 0x000a:
        return ("3des", "sha")
    elif cipher_code == 0x0004:
        return ("rc4", "md5")
    elif cipher_code == 0x0005:
        return ("rc4", "sha")
    else:
        print "Unknown cipher: %04X" % cipher
        return (None, None)

def remove_padding_and_checksum(data, mac):
    plen = struct.unpack("B", data[-1:])[0] + 1
    if mac == "sha":
        plen += 20
    elif mac == "md5":
        plen += 16
    return data[:-plen]

class SSLScanner(StreamScannerFactory):
    """ Collect information about SSL Keys """
    default = True
    group = "NetworkScanners"

    def process_stream(self, stream, factories):
        if stream.dest_port == 31337:
            for (packet_id, cache_offset, data) in stream.packet_data():
                dbh = DB.DBO(self.case)
                try:
                    dbh.insert("sslkeys", packet_id=packet_id, crypt_text=data[:8], key_data=data[8:])
                except DB.DBError:
                    # dont break on re-scan (dupe packet_id), FIXME: should a scanner reset flush the table?
                    pass
        else:
            forward_stream, reverse_stream = self.stream_to_server(stream, "SSL")
            if reverse_stream:
                cipher = None
                mac = None

                # parse the streams, locate the key and add VFS entries if decryption is possible
                fwd_fd = self.fsfd.open(inode_id=forward_stream)
                rev_fd = self.fsfd.open(inode_id=reverse_stream)

                # Skip the initial (unencrypted) chunks, leaving the stream at the correct
                # position. We use a Change Cipher Spec record of length 1 to signal the end of
                # the unencrypted protocol. We process the reverse stream first as it is the 
                # ServerHello which specifies the chosen cipher.
                cipher, mac = (None, None)
                while True:
                    type, data, length = read_chunk(rev_fd)
                    if type == 22 and data[0] == '\x02':
                        (cipher, mac) = parse_handshake(data, length)
                    if type==20 and length==1:
                        break

                if not cipher:
                    print "Unable to find a suitable cipher, cant decrypt this SSL session!"
                    return

                # The first chunk is an encrypted "Handshake Finished" message
                type, data, skiplen = read_chunk(rev_fd)
                type, ciphertext, _ = read_chunk(rev_fd)
                
                # look for the key based upon the first 8-bytes of ciphertext
                dbh = DB.DBO(self.case)
                dbh.execute("select packet_id, key_data from sslkeys where crypt_text=%r", ciphertext[:8])
                row = dbh.fetch()
                if row:
                    print "Found Server decryption keys!\n", dbh.fetch()
                    # we can now add a VFS node for the decrypted content:
                    path,inode,inode_id=self.fsfd.lookup(inode_id=reverse_stream)
                    new_inode = "s%s:%s:%s" % (row['packet_id'], cipher, mac)
                    new_inode_id = self.fsfd.VFSCreate(inode, new_inode, "decrypted")

                # do the same for the forward stream
                while True:
                    type, data, length = read_chunk(fwd_fd)
                    if type==20 and length==1:
                        break

                # The first chunk is an encrypted "Handshake Finished" message
                type, data, skiplen = read_chunk(fwd_fd)
                type, ciphertext, _ = read_chunk(fwd_fd)

                dbh = DB.DBO(self.case)
                dbh.execute("select packet_id, key_data from sslkeys where crypt_text=%r", ciphertext[:8])
                row = dbh.fetch()
                if row:
                    print "Found Client decryption keys!\n", dbh.fetch()
                    # we can now add a VFS node for the decrypted content:
                    path,inode,inode_id=self.fsfd.lookup(inode_id=forward_stream)
                    new_inode = "s%s:%s:%s" % (row['packet_id'], cipher, mac)
                    new_inode_id = self.fsfd.VFSCreate(inode, new_inode, "decrypted")

class SSLCaseTable(FlagFramework.CaseTable):
    """ SSL Table - Stores SSL keys """
    name = 'sslkeys'
    index = 'packet_id'
    primary = 'packet_id'
    
    columns = [
        [ PacketType, {} ],
        [ BlobType, dict(name = 'CryptText', column='crypt_text') ],
        [ BlobType, dict(name = 'KeyData', column='key_data') ],
        ]

class SSLBrowser(Reports.CaseTableReports):
    """ A list of all DNS names seen in the traffic """
    name = "Browse SSL"
    family = "Network Forensics"
    default_table = "SSLCaseTable"
    columns = ['Packet', 'CryptText', 'KeyData']

# A VFS module for decrypting SSL on-the-fly
class SSLFile(File):
    """ A file like object to read data from within SSL connections.
    """
    specifier = 's'
    
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        # grab the key
        this_inode = inode.rsplit('|', 1)[-1][1:]
        packet_id, cipher, mac  = this_inode.split(':')
        dbh = DB.DBO(self.case)
        dbh.execute("select key_data from sslkeys where packet_id=%r", packet_id);
        row = dbh.fetch()
        self.key = row['key_data']

        # lets cheat for now and decrypt the whole file into a buffer...
        while True:
            type, data, length = read_chunk(fd)
            if type==20 and length==1:
                    break

        # The first chunk is an encrypted "Handshake Finished" message
        type, data, skiplen = read_chunk(fd)
        type, ciphertext, _ = read_chunk(fd)
        ciphertext = data+ciphertext

        # decrypt
        if cipher == "3des":
            dec = DES3.new(self.key[8:], DES3.MODE_CBC, self.key[:8])
        elif cipher == "rc4":
            dec = RC4.new(self.key)
        self.buffer = remove_padding_and_checksum(dec.decrypt(ciphertext), mac)[skiplen:]

    def read(self,length=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,length)
        except IOError:
            pass

        if not length or length+self.readptr > len(self.buffer):
            length = len(self.buffer)

        result = self.buffer[self.readptr:length]
        self.readptr += len(result)
        return result

    def seek(self, offset, rel=None):
        File.seek(self,offset,rel)

    def explain(self, query, result):
        self.fd.explain(query, result)

        #result.row("Zip File", "Decompress ZipFileHeader structure at "
        #           "offset %s with length %s" % (self.offset, self.compressed_length))
        #result.row("","Filename - %s" % self.header['zip_path'])
