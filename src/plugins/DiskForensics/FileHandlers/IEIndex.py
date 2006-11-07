# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
""" This Module will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger the scanner off - so its imperative that the TypeScan scanner also be run or this will not work. We also provide a report to view the history files.
"""
import os.path
import pyflag.logging as logging
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.IECache as IECache
import pyflag.DB as DB

class IEIndex(Scanner.GenScanFactory):
    """ Load in IE History files """
    default = True
    depends = ['TypeScan']

    def prepare(self):
        dbh=DB.DBO(self.case)
        dbh.execute("""CREATE TABLE IF NOT EXISTS history (
        `path` TEXT NOT NULL,
        `type` VARCHAR(20) NOT NULL,
        `url` TEXT NOT NULL,
        `modified` TIMESTAMP DEFAULT 0,
        `accessed` TIMESTAMP DEFAULT 0,
        `filename` VARCHAR(250),
        `filepath` VARCHAR(250),
        `headers` TEXT)""")        

    def reset(self, inode):
        Scanner.GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from history")
        
    def destroy(self):
        dbh=DB.DBO(self.case)
        dbh.check_index("history" ,"url",10)

    class Scan(Scanner.StoreAndScanType):
        types = ['application/x-ie-index']

        def external_process(self,fd):
            dbh=DB.DBO(self.case)
            history = IECache.IEHistoryFile(fd)
            for event in history:
                if event:                    
                    dbh.execute("INSERT INTO history VALUES(%r,%r,%r,%r,%r,%r,%r,%r)",(
                        self.ddfs.lookup(inode=self.inode),
                        event['type'],event['url'],
                        event['modified_time'],
                        event['accessed_time'],
                        event['filename'],
                        '',event['data']
                        )
                                     )

class IEHistory(Reports.report):
    """ View IE browsing history with pasco"""
    name = "IE Browser History (pasco)"
    family = "Disk Forensics"
    description="This report will display all IE browsing history data found in index.dat files"
    def form(self,query,result):
        result.case_selector()
        
    def display(self,query,result):
        result.heading("IE History")
        dbh=self.DBO(query['case'])

        try:
            result.table(
                columns=('path','type','url','modified','accessed','concat(filepath,filename)','headers'),
                names=('Path','Type','URL','Modified','Accessed','Filename','Headers'),
                table=('history'),
                case=query['case']
                )
        except DB.DBError,e:
            result.para("Error reading the history table. Did you remember to run the IEHistory scanner?")
            result.para("Error reported was:")
            result.text(e,color="red")
