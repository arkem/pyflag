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
import Crypto.Cipher.AES as AES
import pyflag.Scanner as Scanner
import pyflag.CacheManager as CacheManager
import posixpath

config.add_option("SSL_PORTS", default='[443,]',
                  help="A list of ports to be considered for SSL transactions")

ssl_packet_psk = "lettherebelight"

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
    #print type, length
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
    elif cipher_code in (0x0039, 0x0035, 0x002f):
        return ("aes", "sha")
    else:
        print "Unknown cipher: %04X" % cipher_code
        return (None, None)

def remove_padding_and_checksum(data, cipher, mac):
    if cipher == "3des" or cipher == "aes":
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

    def complete_stream(self, forward_id, reverse_id, factories):
    
        dbh = DB.DBO(self.case)

        # complete the processing of both streams
        new_ids = []
        for inode_id in (forward_id, reverse_id):
            # get a new inode_id, inode, path
            dbh.insert('inode', _inode_id='NULL', _fast=True)
            new_inode_id = dbh.autoincrement()
            dbh.delete('inode', where='inode_id = %s' % new_inode_id)

            path, inode, _ = self.fsfd.lookup(inode_id=inode_id)
            new_inode = "%s|S%d" % (inode, new_inode_id)
            new_path = "%s/decrypted" % path

            # decrypt the stream, and as we do, build the connection
            # tables to refer back to the original packets
            dbh.execute("select packet_id, cipher, mac, key_data from sslkeys where inode_id=%r", inode_id)
            row = dbh.fetch()

            cipher = row['cipher']
            mac = row['mac']
            key = row['key_data']

            # setup cipher
            if cipher == "3des":
                dec = DES3.new(key[8:], DES3.MODE_CBC, key[:8])
            elif cipher == "rc4":
                dec = RC4.new(key)
            elif cipher == "aes":
                dec = AES.new(key[16:], AES.MODE_CBC, key[:16])
            else:
                print "unsupported cipher %s" % cipher

            # skip the unencrypted stuff
            fd = self.fsfd.open(inode_id = inode_id)
            while True:
                type, data, length = read_chunk(fd)
                if type==20 and length==1:
                    break

            # The first chunk is an encrypted "Handshake Finished" message
            type, data, skiplen = read_chunk(fd)
            remove_padding_and_checksum(dec.decrypt(data), cipher, mac)
            
            # create a cache file
            out_fd = CacheManager.MANAGER.create_cache_fd(dbh.case, new_inode, inode_id=new_inode_id)
            out_fd_len = 0
            while True:
                try:
                    type, ciphertext, length = read_chunk(fd)
                    data = remove_padding_and_checksum(dec.decrypt(ciphertext), cipher, mac)
                    # copy a "packet" entry for this ssl record, updating the length and cache_offset fields
                    dbh.execute("insert into connection (inode_id, packet_id, seq, length, cache_offset) (select %r, packet_id, %r, %r, %r from connection where packet_id=%r)", (new_inode_id, out_fd_len, len(data), out_fd_len, fd.get_packet_id()))
                    out_fd.write(data)
                    out_fd_len += len(data)
                except (struct.error, TypeError), e:
                    print "Got Error during SSL Record decryption: %s" % e
                    break

            out_fd.close()
            # Get mtime 
            try:
                dbh.execute("select pcap.ts_sec from pcap where pcap.id=%r", fd.get_packet_id(0))
                metamtime=dbh.fetch()['ts_sec']
            except (DB.DBError, TypeError), e:
                pyflaglog.log(pyflaglog.WARNING, "Failed to determine mtime of newly created stream %s" % self.inode)
                metamtime=None

            # add a VFS entry using the stream VFS ('S')
            self.fsfd.VFSCreate(None, new_inode, new_path, size=out_fd_len, mtime=metamtime, inode_id=new_inode_id)
            
            # record the new_id
            new_ids.append(new_inode_id)
        
        # now that we know both new_ids, add to the connection table
        dbh.execute("insert into connection_details (inode_id, reverse, src_ip, src_port, dest_ip, dest_port, isn, ts_sec, type) (select %r, %r, src_ip, src_port, dest_ip, dest_port, isn, ts_sec, type from connection_details where inode_id=%r)", (new_ids[0], new_ids[1], forward_id))
        dbh.execute("insert into connection_details (inode_id, reverse, src_ip, src_port, dest_ip, dest_port, isn, ts_sec, type) (select %r, %r, src_ip, src_port, dest_ip, dest_port, isn, ts_sec, type from connection_details where inode_id=%r)", (new_ids[1], new_ids[0], reverse_id))
            
        # scan both new inodes
        for inode in new_ids:
            fd = self.fsfd.open(inode_id = inode)
            Scanner.scanfile(self.fsfd, fd, factories)

    def process_stream(self, stream, factories):
        if stream.dest_port in(31337, 23456, 5350):
            for (packet_id, cache_offset, data) in stream.packet_data():
                dbh = DB.DBO(self.case)
                try:
                    # decrypt the key:
                    dec = RC4.new(ssl_packet_psk)
                    # see if there is already an entry for this stream
                    dbh.execute("select inode_id from sslkeys where crypt_text=%r", data[:8])
                    row = dbh.fetch()
                    if row:
                        inode_id = row['inode_id']
                        dbh.execute("update sslkeys set packet_id=%r, key_data=%r where inode_id=%r", (packet_id, dec.decrypt(data[10:]), inode_id))

                        # only call complete when both forward and reverse streams are ready
                        dbh.execute("select sslkeys.inode_id, packet_id from sslkeys,connection_details where sslkeys.inode_id=connection_details.inode_id and reverse=%r", inode_id)
                        row = dbh.fetch()
                        if row and row['packet_id']:
                            print "UDP Scanner: KEY complete for connection(%s/%s)" % (inode_id, row['inode_id'])
                            if inode_id < row['inode_id']:
                                self.complete_stream(inode_id, row['inode_id'], factories)
                            else:
                                self.complete_stream(row['inode_id'], inode_id, factories)
                    else:
                        dbh.insert("sslkeys", packet_id=packet_id, crypt_text=data[:8], key_data=dec.decrypt(data[10:]))

                except DB.DBError, e:
                    print "Got DB Error: %s" % e
                    # dont break on re-scan (dupe packet_id), FIXME: should a scanner reset flush the table?
                    pass
        else:
            forward_stream, reverse_stream = self.stream_to_server(stream, "SSL")
            if reverse_stream:
                try:
                    fwd_fd = self.fsfd.open(inode_id=forward_stream)
                    rev_fd = self.fsfd.open(inode_id=reverse_stream)
                except IOError:
                    return

                fwd_done, rev_done = (False, False)
                # Skip the initial (unencrypted) chunks, leaving the stream at the correct
                # position. We use a Change Cipher Spec record of length 1 to signal the end of
                # the unencrypted protocol. We process the reverse stream first as it has the 
                # ServerHello which specifies the chosen cipher.
                cipher, mac = (None, None)
                try:
                    while True:
                        type, data, length = read_chunk(rev_fd)
                        if type == 22 and data[0] == '\x02':
                            (cipher, mac) = parse_handshake(data, length)
                        if type==20 and length==1:
                            break
                except (struct.error, TypeError):
                    return

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
                    fwd_done = True
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
                    rev_done = True
                else:
                    dbh.insert("sslkeys", inode_id=forward_stream, cipher=cipher, mac=mac, crypt_text=ciphertext[:8])

                if(fwd_done and rev_done):
                    print "SSL Scanner: KEY complete for stream(%s/%s)" % (forward_stream, reverse_stream)
                    self.complete_stream(forward_stream, reverse_stream, factories)

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
