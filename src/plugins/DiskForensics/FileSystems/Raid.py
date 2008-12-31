""" This is a raid IO Source implementation. """
import plugins.Images as Images
import pyflag.FlagFramework as FlagFramework
import pyflag.IO as IO
import re, os.path

class RAIDFD(Images.OffsettedFDFile):
    """ A RAID file like object - must be initialised with the correct parameters """
    def __init__(self, fds, blocksize, map, offset):
        self.readptr = 0
        self.fds = fds
        ## The number of disks in the set
        self.disks = len(fds)
        self.blocksize = blocksize
        self.parse_map(map)
        self.offset = offset
        ## We estimate the size:
        fds[0].seek(0,2)
        self.size = fds[0].tell() * self.physical_period

    def seek(self, offset, whence=0):
        """ fake seeking routine """
        readptr = self.readptr
        if whence==0:
            readptr = offset + self.offset
        elif whence==1:
            readptr += offset
        elif whence==2:
            readptr = self.size

        if readptr < self.offset:
            raise IOError("Seek before start of file")

        self.readptr = readptr

    def parse_map(self, map):
        elements = map.split(".")
        ## The physical period is the number of blocks before the map
        ## repeats in each disk
        self.physical_period = len(elements)/len(self.fds)

        self.map = []
        while len(elements)>0:
            self.map.append([])
            for i in range(self.disks):
                try:
                    disk_number = int(elements.pop(0))
                except: disk_number=None
                
                self.map[-1].append(disk_number)

        self.period_map = []
        for i in range((self.physical_period -1) * self.disks):
            found = False
            ## Find the required disk in the map:
            for period_index in range(len(self.map)):
                try:
                    d = self.map[period_index].index(i)
                    self.period_map.append((period_index,d))
                    found = True
                    break
                except: pass

            if not found:
                print "position %s not found" % i
            
        self.logical_period_size = len(self.period_map)
        
    def partial_read(self, length):
        ## calculate the current position within the logical
        ## image. Logical blocks refer to the reconstituted image,
        ## physical to the raw disks
        logical_block_number = self.readptr / self.blocksize
        logical_block_offset = self.readptr % self.blocksize

        ## Our logical block position within the period
        logical_period_position = logical_block_number % self.logical_period_size
        logical_period_number = logical_block_number / self.logical_period_size

        ## Now work out which disk is needed.
        physical_period_number, disk_number = self.period_map[logical_period_position]

        ## Now the physical block within the disk:
        physical_block_number = logical_period_number * self.physical_period \
                                + physical_period_number

        ## Now fetch the data
        to_read = min(self.blocksize - logical_block_offset, length)

        self.fds[disk_number].seek(self.blocksize * physical_block_number \
                                   + logical_block_offset)
        data = self.fds[disk_number].read(to_read)
        self.readptr += to_read
        
        return data


class RAID(Images.Standard):
    """ RAID image sets """
    name = 'RAID5 (1 Parity)'
    
    def form(self, query, result):
        ## Some reasonable defaults to get you started
        query.default('blocksize','4k')
        query.default('period','3')
        query.default('map','1.0.P.2.P.3.P.5.4')
        keys = []
        values = []
        result.fileselector("Disks", name='filename')
        result.textfield("Block size",'blocksize')
        result.textfield("Period",'period')
        self.calculate_map(query, result)
        self.calculate_partition_offset(query, result)

    def calculate_map(self, query,result):
        """ Present the GUI for calculating the map """
        def map_popup(query,result):
            result.decoration = 'naked'
            try:
                map = str(query['map']).split('.')
            except KeyError:
                map = []

            result.start_form(query)
            ## Open all the disks
            filenames = query.getarray('filename') 
            fds = [ IO.open_URL(f) for f in filenames ]
            uis = [ result.__class__(result) for f in filenames ]

            period_number = int(query.get('period_number',0))
            blocksize = FlagFramework.calculate_offset_suffix(query['blocksize'])
            period = FlagFramework.calculate_offset_suffix(query['period'])
            logical_period_size = period * (len(fds)-1)
            ## Let the user know our disk offset
            result.para("Disk Offset is %s (%s periods)" %  (blocksize  * (period_number * period), period_number))

            if query.has_key("__submit__"):
                ## Build the new map variable
                query.clear('map')
                map = []
                for x in range(period * len(fds)):
                    map.append(query['position_%s' % x])
                    query.clear('position_%s' % x)
                    
                query['map'] = '.'.join(map)
                result.refresh(0,query,pane='parent')
                return result
            
            ## Possible positions the block can be
            positions = ['P', ] + [ str(x) for x in range(logical_period_size) ]

            for i in range(len(fds)):
                uis[i].heading(os.path.basename(filenames[i]))
                ## Display the start and end of each physical block in
                ## the period:
                ## Count is the position of each block in the map
                count = i
                for p in range(period):
                    ui = uis[i]
                    fd = fds[i]
                    
                    ## This offset of this block
                    offset = blocksize  * (p + period_number * period)
                    fd.seek(offset)
                    ui.ruler()
                    for j in range(4):
                        data = fd.read(16)
                        data = re.sub(r'[\r\n\t]','.',data)
                        ui.text(data + "    \n", sanitise='full', font='typewriter')

                    ui.start_table()
                    try:
                        ui.defaults.default("position_%s" % count, map[count])
                    except IndexError: raise


                    ui.const_selector("Pos", "position_%s" % count,positions,positions)
                    ui.end_table()
                    fd.seek(offset + blocksize - 16*4)                    
                    for j in range(4):
                        data = fd.read(16)
                        data = re.sub(r'[\r\n\t]','.',data)
                        ui.text(data + "    \n", sanitise='full', font='typewriter')
                    ui.ruler()
                    count += period
            
            result.row(*uis)
            result.end_form()
            result.para("Press submit to update the map definition")
            query.set('period_number',max(period_number-1, 0))
            if period_number >0:
                result.toolbar(text='Previous Period', icon='stock_left.png',
                               link = query, pane='self')
            else:
                result.toolbar(text='Previous Period', icon='stock_left_gray.png',
                               pane='self')

            query.set('period_number',period_number+1)
            result.toolbar(text='Next Period', icon='stock_right.png',
                           link = query, pane='self')

            result.toolbar(text="Skip to text region", icon='stock_last.png',
                           cb = self.search_next_text_region, pane='popup')

            result.toolbar(text='goto period', icon='stock_next-page.png',
                           cb = self.goto_period, pane='popup')

        tmp = result.__class__(result)
        tmp2 = result.__class__(result)
        tmp2.popup(map_popup,
                   "Calculate the RAID map",
                   pane='new',
                   icon='examine.png')

        tmp.row(tmp2, "Map")
        result.textarea(tmp,'map')

    ## This regex matches a continuous string with only printables
    text_re = re.compile(r"^[\t\n\r !\"#$%&\'()*+,\-./0123456789:;" \
                         r"<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]^_`a" \
                         r"bcdefghijklmnopqrstuvwxyz{|}~]+$")

    def goto_period(self, query,result):
        """ Jumps to specified period """
        result.heading("Jump to period")
        if query.has_key("__submit__" ):
            query.set('period_number',query['goto_period'])
            query.clear('goto_period')

            result.refresh(0, query, 'parent')
            return
        
        result.start_form(query)
        result.textfield("Period Number to jump to", 'goto_period')
        result.end_form()

    def search_next_text_region(self, query, result):
        """ searches for the next text region and updates query['period_number'] """
        ## Open all the disks
        filenames = query.getarray('filename') 
        fds = [ IO.open_URL(f) for f in filenames ]
        period_number = int(query.get('period_number',0)) + 1
        blocksize = FlagFramework.calculate_offset_suffix(query['blocksize'])
        period = FlagFramework.calculate_offset_suffix(query['period'])

        p=0
        while 1:
            offset = blocksize  * (p + period_number * period)
            for fd in fds:
                fd.seek(offset)
                ## We classify a text region as one with 20 chars at
                ## the start of the period
                data = fd.read(20)
                if not data:
                    result.heading("Error")
                    result.para("Unable to read data from %r" % fd)
                    return
                
                m = self.text_re.match(data)
                if m:
                    period_number = period_number + p / period
                    query.set('period_number',period_number)
                    result.refresh(0, query, 'parent')
                    return

                p += 1

    def create(self, name,case, query):
        offset = FlagFramework.calculate_offset_suffix(query.get('offset','0'))
        filenames = self.glob_filenames(query.getarray('filename'))
        ## FIXME - allow arbitrary IO Source URLs here
        fds = [ open(f) for f in filenames ]
        blocksize = FlagFramework.calculate_offset_suffix(query.get('blocksize','32k'))
        return RAIDFD(fds, blocksize, query['map'], offset)
