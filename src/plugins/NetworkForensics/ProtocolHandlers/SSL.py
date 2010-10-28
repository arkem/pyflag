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
from pyflag.FileSystem import File, DBFS
import Crypto.Cipher.DES3 as DES3
import Crypto.Cipher.ARC4 as RC4
import pyflag.Scanner as Scanner
import posixpath

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

def remove_padding_and_checksum(data, cipher, mac):
    if cipher == "3des":
        plen = struct.unpack("B", data[-1:])[0] + 1
    else:
        plen = 0

    if mac == "sha":
        plen += 20
    elif mac == "md5":
        plen += 16
    return data[:-plen]

class SSLScanner(StreamScannerFactory):
    """ Collect information about SSL Keys """
    default = True
    group = "NetworkScanners"

    def complete_stream(self, inode_id, factories):
        # we can now add a VFS node for the decrypted content:
        dbh = DB.DBO(self.case)
        dbh.execute("select cipher, mac, packet_id from sslkeys where inode_id=%r", inode_id)
        row = dbh.fetch()
        path,inode,inode_id=self.fsfd.lookup(inode_id=inode_id)
        new_inode_id = self.fsfd.VFSCreate(inode, "s%d" % inode_id, "decrypted")

        # scan it!
        fd = self.fsfd.open(inode_id = new_inode_id)
        Scanner.scanfile(self.fsfd, fd, factories)

        # add a VFS entry for the combined stream if it doesnt already exits
        # and we have processed both the forward and reverse streams
        try:
            fd = self.fsfd.open(inode_id=inode_id)
            parent = "".join(inode.split('|')[:-1])
            reverse_inode = "%s|S%d|s%d" % (parent, fd.reverse, fd.reverse)
            self.fsfd.open(inode=reverse_inode) # raises if the stream can't be opened yet (no keys)
            new_path = "%s/combined_decrypted" % path[:path.rfind("/")]

            if not self.fsfd.exists(new_path):
                print "Creating Combined VFS"
                if inode_id < fd.reverse:
                    new_inode = "%s|s%d/%d" % (parent, inode_id, fd.reverse)
                else:
                    new_inode = "%s|s%d/%d" % (parent, fd.reverse, inode_id)
                new_inode_id = self.fsfd.VFSCreate(None, new_inode, new_path)

                # scan it!
                fd = self.fsfd.open(inode_id = new_inode_id)
                Scanner.scanfile(self.fsfd, fd, factories)

                # also poke the HTTP scanner directly if selected
                for scanner in factories:
                    if str(scanner.__class__) == "HTTP.HTTPScanner":
                        print "Calling HTTP Scanner!"
                        scanner.process_stream(fd, factories)

        except (IOError, TypeError), e:
            # reverse stream not available yet
            pass

    def process_stream(self, stream, factories):
        if stream.dest_port == 31337:
            for (packet_id, cache_offset, data) in stream.packet_data():
                dbh = DB.DBO(self.case)
                try:
                    # see if there is already an entry for this stream
                    dbh.execute("select inode_id from sslkeys where crypt_text=%r", data[:8])
                    row = dbh.fetch()
                    if row:
                        dbh.execute("update sslkeys set packet_id=%r, key_data=%r where inode_id=%r", (packet_id, data[8:], row['inode_id']))
                        print "UDP Scanner: KEY complete for inode_id: %s" % row['inode_id']
                        self.complete_stream(row['inode_id'], factories)
                    else:
                        dbh.insert("sslkeys", packet_id=packet_id, crypt_text=data[:8], key_data=data[8:])

                except DB.DBError:
                    # dont break on re-scan (dupe packet_id), FIXME: should a scanner reset flush the table?
                    pass
        else:
            forward_stream, reverse_stream = self.stream_to_server(stream, "SSL")
            if reverse_stream:
                fwd_fd = self.fsfd.open(inode_id=forward_stream)
                rev_fd = self.fsfd.open(inode_id=reverse_stream)

                # Skip the initial (unencrypted) chunks, leaving the stream at the correct
                # position. We use a Change Cipher Spec record of length 1 to signal the end of
                # the unencrypted protocol. We process the reverse stream first as it has the 
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
                dbh.execute("select packet_id from sslkeys where crypt_text=%r", ciphertext[:8])
                row = dbh.fetch()
                if row:
                    dbh.execute("update sslkeys set inode_id=%r, cipher=%r, mac=%r where packet_id=%r", (reverse_stream, cipher, mac, row['packet_id']))
                    print "SSL Scanner: KEY complete for inode_id: %s" % reverse_stream
                    self.complete_stream(reverse_stream, factories)
                else:
                    dbh.insert("sslkeys", inode_id=reverse_stream, cipher=cipher, mac=mac, crypt_text=ciphertext[:8])

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
                    dbh.execute("update sslkeys set inode_id=%r, cipher=%r, mac=%r where packet_id=%r", (forward_stream, cipher, mac, row['packet_id']))
                    print "SSL Scanner: KEY complete for inode_id: %s" % forward_stream
                    self.complete_stream(forward_stream, factories)
                else:
                    dbh.insert("sslkeys", inode_id=forward_stream, cipher=cipher, mac=mac, crypt_text=ciphertext[:8])

class SSLCaseTable(FlagFramework.CaseTable):
    """ SSL Table - Stores SSL keys """
    name = 'sslkeys'
    #index = 'packet_id'
    #primary = 'packet_id'
    
    columns = [
        [ InodeIDType, {} ],
        [ PacketType, {} ],
        [ StringType, dict(name = 'Cipher', column = 'cipher') ],
        [ StringType, dict(name = 'MAC', column = 'mac') ],
        [ BlobType, dict(name = 'CryptText', column = 'crypt_text') ],
        [ BlobType, dict(name = 'KeyData', column = 'key_data') ],
        ]

class SSLBrowser(Reports.CaseTableReports):
    """ A list of all DNS names seen in the traffic """
    name = "Browse SSL"
    family = "Network Forensics"
    default_table = "SSLCaseTable"
    columns = ['Inode', 'Packet', 'Cipher', 'MAC', 'CryptText', 'KeyData']

# A VFS module for decrypting SSL on-the-fly
class SSLFile(File):
    """ A file like object to read data from within SSL connections.
    """
    specifier = 's'
    
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        this_inode = inode.rsplit('|', 1)[-1][1:]
        if not '/' in this_inode:
            dbh = DB.DBO(self.case)
            dbh.execute("select cipher, mac, key_data from sslkeys where inode_id=%r", this_inode);
            row = dbh.fetch()
            cipher = row['cipher']
            mac = row['mac']
            self.key = row['key_data']

            # lets cheat for now and decrypt the whole file into a buffer...
            while True:
                type, data, length = read_chunk(fd)
                if type==20 and length==1:
                        break

            # setup cipher
            if cipher == "3des":
                dec = DES3.new(self.key[8:], DES3.MODE_CBC, self.key[:8])
            elif cipher == "rc4":
                dec = RC4.new(self.key)
            else:
                print "unsupported cipher %s" % cipher

            # The first chunk is an encrypted "Handshake Finished" message
            type, data, skiplen = read_chunk(fd)
            remove_padding_and_checksum(dec.decrypt(data), cipher, mac)
            
            self.buffer = ""
            while True:
                try:
                    type, ciphertext, length = read_chunk(fd)
                    self.buffer += remove_padding_and_checksum(dec.decrypt(ciphertext), cipher, mac)
                except (struct.error, TypeError), e:
                    break

        else:
            # This is a combined stream
            id_fwd, id_rev = this_inode.split('/')
            fsfd = DBFS(self.case)
            fd_fwd = fsfd.open(inode_id=id_fwd)
            fd_rev = fsfd.open(inode_id=id_rev)

            # setup cipher
            dbh = DB.DBO(self.case)
            dbh.execute("select cipher, mac, key_data from sslkeys where inode_id=%r", id_fwd)
            row_fwd = dbh.fetch()
            dbh.execute("select cipher, mac, key_data from sslkeys where inode_id=%r", id_rev)
            row_rev = dbh.fetch()

            cipher, mac = (row_fwd['cipher'], row_fwd['mac'])
            if cipher == "3des":
                dec_fwd = DES3.new(row_fwd['key_data'][8:], DES3.MODE_CBC, row_fwd['key_data'][:8])
                dec_rev = DES3.new(row_rev['key_data'][8:], DES3.MODE_CBC, row_rev['key_data'][:8])
            elif cipher == "rc4":
                dec_fwd = RC4.new(row_fwd['key_data'])
                dec_rev = RC4.new(row_rev['key_data'])
            else:
                print "unsupported cipher %s" % cipher
                return

            # skip the unencrypted parts of each stream
            for fd, dec in ((fd_fwd, dec_fwd), (fd_rev, dec_rev)):
                while True:
                    type, data, length = read_chunk(fd)
                    if type==20 and length==1:
                            break

                # The next chunk is an encrypted "Handshake Finished" message
                type, data, _ = read_chunk(fd)
                remove_padding_and_checksum(dec.decrypt(data), cipher, mac)

            # now we are ready to process the encrypted records
            self.buffer = ""
            fwd, rev = (True, True)
            while fwd and rev:
                pkt_fwd = fd_fwd.get_packet_id(fd_fwd.readptr+1)
                pkt_rev = fd_rev.get_packet_id(fd_rev.readptr+1)
                if pkt_fwd and pkt_fwd < pkt_rev:
                    try:
                        type, data, length = read_chunk(fd_fwd)
                        self.buffer += remove_padding_and_checksum(dec_fwd.decrypt(data), cipher, mac)
                    except TypeError, struct.error:
                        fwd = False
                else:
                    try:
                        type, data, length = read_chunk(fd_rev)
                        self.buffer += remove_padding_and_checksum(dec_rev.decrypt(data), cipher, mac)
                    except TypeError, struct.error:
                        rev = False

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
