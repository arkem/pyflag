""" This module analyses unallocated and slack space.

Basically it creates Virutual File System (VFS) objects for each stream of unallocated space. Such streams are found at the end of allocated blocks (slack space) as well as completely unallocated blocks. The unallocated blocks are then searched for files using the Exgrep technique. If files are found in the unallocated vfs files, the new VFS nodes are created for them and they are further scanned.

This has the effect of locating zip files in unallocated space and recursively openning them, performing keyword searchs etc.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import zipfile,gzip
from pyflag.FileSystem import File
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import pyflag.Exgrep as Exgrep

#hidden = True

class UnallocatedScan(GenScanFactory):
    """ Scan unallocated space for files.

    Unallocated space is defined as slack space (the space between the end of a file and the next block alignments) as well as unallocated blocks. This does not include allocated blocks which simply do not have file entries (e.g. deleted files).
    """
    order=100
    def reset(self):
        self.dbh.execute("drop table if exists unallocated_%s" ,self.table)

    def prepare(self):
        """ Creates the unallocated VFS nodes at scanner initialisation.

        This works because scanners are invoked after all the physical Inodes are created in the blocks table - so we have visibility of allocated nodes. Note that VFS objects do not count since they typically do not have block allocations.
        """
        ## We remove older tables to ensure we always have the latest up to date table.
        self.dbh.execute("drop table if exists unallocated_%s" ,self.table)
        self.dbh.execute("CREATE TABLE unallocated_%s (`inode` VARCHAR(50) NOT NULL,`offset` BIGINT NOT NULL,`size` BIGINT NOT NULL)",self.table)
        unalloc_blocks = []
        count=0
        ## Now we work out the unallocated blocks by looking at the blocks table:
        last = (0,0)
        self.dbh.execute("select * from block_%s order by block asc", self.table)
        dbh2 = self.dbh.clone()
        for row in self.dbh:
            ## We make a list of all blocks which are unallocated:
            ## This is the end of the unallocated block just before this one:
            new_block = ( last[0],row['block']-last[0])
            if new_block[1]>0:
                ## Add the offset into the db table:
                offset = new_block[0] * self.fsfd.block_size
                size = new_block[1] * self.fsfd.block_size
                dbh2.execute("insert into unallocated_%s set inode='U%s',offset=%r,size=%r",(
                    self.table, count, offset, size))

                ## Add a new VFS node:
                self.fsfd.VFSCreate(None,'U%s' % count, "/_unallocated_/%s" % offset, size=size)
                count+=1
                unalloc_blocks.append(new_block)

            last=(row['block']+row['count'],0,row['inode'])

    class Scan:                
        def __init__(self, inode,ddfs,outer,factories=None):
            self.inode=inode
            self.ddfs=ddfs
            self.outer=outer
            self.factories=factories
            
        def process(self,data,metadata=None):
            if self.inode.startswith('U'):
                for cut in Exgrep.process_string(data):
                    ## Create a VFS node:
                    self.outer.fsfd.VFSCreate(self.inode,'U%s' % cut['offset'],"%s.%s" % (cut['offset'],cut['type']),size=cut['length'])
                    self.outer.dbh.execute("insert into unallocated_%s set inode='%s|U%s',offset=%r,size=%r" , (self.outer.table,self.inode,cut['offset'],cut['offset'],cut['length']))

        def finish(self):
            pass

## Deleted files scanner:
class DeletedScan(GenScanFactory):
    """ Create VFS nodes for deleted files.

    Deleted files are those which are allocated by the filesystem, but do not have a file entry. This makes them impossible to view through the normal GUI. By creating file table entries for those it is possible to view these inodes using the same GUI.
    """
    order=5
    def prepare(self):
        """ Create the extra file entries in the file table.

        This scanner just inserts more entries into the file table. This means it needs intimate knowledge of the file/inode schema (rather than using the VFSCreate API). Since this scanner needs to have intimate knowledge of the schema to work out which inodes are deleted, this is probably ok. By inserting extra file entries, we dont need to have a VFS driver too. 
        """
        ## Create a deleted directory entry:
        dbh2=self.dbh.clone()
        self.dbh.execute("insert into file_%s set  inode='D0',mode='d/d',status='alloc',path='/',name='_deleted_'",self.table)
        ## This will give us all the inodes which appear in the blocks
        ## table (i.e. they are allocated), but do not appear in the
        ## file table (i.e. do not have a filename).
        self.dbh.execute("select a.inode as inode from block_%s as a left join file_%s as b on a.inode=b.inode where isnull(b.inode) group by a.inode",(self.table,self.table))
        for row in self.dbh:
            dbh2.execute("insert into file_%s set inode=%r,mode='r/r',status='alloc',path='/_deleted_/',name=%r",(self.table,row['inode'],row['inode']))

## Unallocated space VFS Driver:
class Unallocated_File(FileSystem.File):
    """ A VFS driver for reading unallocated space off the disk.

    This driver reads the offset from the unallocated table which was previously prepared by the unallocated scanner.
    """
    specifier = 'U'
    
    def __init__(self,case,table,fd,inode):
        File.__init__(self, case, table, fd, inode)
        self.fd=fd
        self.dbh = DB.DBO(case)
        self.dbh.execute("select * from unallocated_%s where inode=%r",(table,inode))
        row=self.dbh.fetch()
        self.size=row['size']
        self.offset=row['offset']

    def read(self,length=None):
        if (length == None) or ((length + self.readptr) > self.size):
            length = self.size - self.readptr

        if length == 0:
            return ''

        self.fd.seek(self.readptr+self.offset)
        result =self.fd.read(length)
        self.readptr+=len(result)
        return result