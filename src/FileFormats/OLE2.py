#!/usr/bin/env python
""" This module handles OLE2 files, such as Microsoft office files.

We currently implement support for the following file formats:
outlook .msg files - These get extracted into the normal vfs - we also collect stats on the file
MS Office - We collect metadata in a special report.

Generic OLE VFS - The contents of the OLE file is made available through the VFS
"""
from libole2 import OLEFile
from format import *
from plugins.FileFormats.BasicFormats import *
import sys,re
from plugins.FileFormats.BasicFormats import *
import cStringIO

prop_lookup = {
    '001A': 'Message class',
    '0037': 'Subject',
    '003D': 'Subject prefix',
    '0040': 'Received by name',
    '0042': 'Sent repr name',
    '0044': 'Rcvd repr name',
    '004D': 'Org author name',
    '0050': 'Reply rcipnt names',
    '005A': 'Org sender name',
    '0064': 'Sent repr adrtype',
    '0065': 'Sent repr email',
    '0070': 'Topic',
    '0075': 'Rcvd by adrtype',
    '0076': 'Rcvd by email',
    '0077': 'Repr adrtype',
    '0078': 'Repr email',
    '007d': 'Message header',
    '0C1A': 'Sender name',
    '0C1E': 'Sender adr type',
    '0C1F': 'Sender email',
    '0E02': 'Display BCC',
    '0E03': 'Display CC',
    '0E04': 'Display To',
    '0E1D': 'Subject (normalized)',
    '0E28': 'Recvd account1(?)',
    '0E29': 'Recvd account2(?)',
    '1000': 'Message body',
    '1008': 'RTF sync body tag',
    '1035': 'Message ID (?)',
    '1046': 'Sender email(?)',
    '3001': 'Display name',
    '3002': 'Address type',
    '3003': 'Email address',
    '39FE': '7-bit email (?)',
    '39FF': '7-bit display name',
    '3701': 'Attachment data',
    '3703': 'Attach extension',
    '3704': 'Attach filename',
    '3707': 'Attach long filenm',
    '370E': 'Attach mime tag',
    '3712': 'Attach ID (?)',
    '3A00': 'Account',
    '3A02': 'Callback phone no',
    '3A05': 'Generation',
    '3A06': 'Given name',
    '3A08': 'Business phone',
    '3A09': 'Home phone',
    '3A0A': 'Initials',
    '3A0B': 'Keyword',
    '3A0C': 'Language',
    '3A0D': 'Location',
    '3A11': 'Surname',
    '3A15': 'Postal address',
    '3A16': 'Company name',
    '3A17': 'Title',
    '3A18': 'Department',
    '3A19': 'Office location',
    '3A1A': 'Primary phone',
    '3A1B': 'Business phone 2',
    '3A1C': 'Mobile phone',
    '3A1D': 'Radio phone no',
    '3A1E': 'Car phone no',
    '3A1F': 'Other phone',
    '3A20': 'Transmit dispname',
    '3A21': 'Pager',
    '3A22': 'User certificate',
    '3A23': 'Primary Fax',
    '3A24': 'Business Fax',
    '3A25': 'Home Fax',
    '3A26': 'Country',
    '3A27': 'Locality',
    '3A28': 'State/Province',
    '3A29': 'Street address',
    '3A2A': 'Postal Code',
    '3A2B': 'Post Office Box',
    '3A2C': 'Telex',
    '3A2D': 'ISDN',
    '3A2E': 'Assistant phone',
    '3A2F': 'Home phone 2',
    '3A30': 'Assistant',
    '3A44': 'Middle name',
    '3A45': 'Dispname prefix',
    '3A46': 'Profession',
    '3A48': 'Spouse name',
    '3A4B': 'TTYTTD radio phone',
    '3A4C': 'FTP site',
    '3A4E': 'Manager name',
    '3A4F': 'Nickname',
    '3A51': 'Business homepage',
    '3A57': 'Company main phone',
    '3A58': 'Childrens names',
    '3A59': 'Home City',
    '3A5A': 'Home Country',
    '3A5B': 'Home Postal Code',
    '3A5C': 'Home State/Provnce',
    '3A5D': 'Home Street',
    '3A5F': 'Other adr City',
    '3A60': 'Other adr Country',
    '3A61': 'Other adr PostCode',
    '3A62': 'Other adr Province',
    '3A63': 'Other adr Street',
    '3A64': 'Other adr PO box',
    '3FF7': 'Server',
    '3FF8': 'Creator1',
    '3FFA': 'Creator2',
    '3FFC': 'To email',
    '403D': 'To adrtype',
    '403E': 'To email',
    '5FF6': 'To',
    }

def mesg_property(p,file):
    name = p['pps_rawname'].__str__()
    m = re.match('__substg1.0_(....)(....)',name)
    prop_id = m.group(1)
    type=m.group(2)
    
    try:
        property_name=prop_lookup[prop_id]
    except:
        return
        property_name="Unknown property ID %s" % prop_id
        
    data=file.cat(p)

    ## Convert to utf-8 if possible
    try:
        data = data.decode("utf-16").encode('utf-8')
    except Exception,e:
        pass
    
    yield property_name, data

def mesg_attach(p,file):
    yield ('','')

def mesg_receipt(p,file):
    yield ('','')

class FIDAndOffset(SimpleStruct):
    fields=[
        [ 'FID', CLSID],
        [ 'offset',LONG]
        ]

class FIDAndOffsetArray(ARRAY):
    target_class=FIDAndOffset

class PropHeader(SimpleStruct):
    fields=[
        [ 'byteOrder',WORD],
        [ 'Format',WORD],
        [ 'OSVersion1',WORD],
        [ 'OSVersion2',WORD],
        [ 'ClassID',CLSID],
        [ 'cSections',LONG],
        ]

class DataSize(SimpleStruct):
    fields=[
        [ 'cBytes',LONG],
        [ 'cProps',LONG],
        ]

class PropDataType(LONG_ENUM):
    """ These are the possible data types in properties """
    types = {
        0x03: LONG,
        0x1e: LPSTR,
        0x40: WIN_FILETIME,
        }

class PropType(LONG_ENUM):
    """ These are some of the properties that we know about.
    
    This list is not exhaustive.
    """
    types = {
        0x02:'Title',
        0x03:'Subject',
        0x04:'Author',
        0x05:'Keywords',
        0x06:'Comments',
        0x07:'Template',
        0x08:'Lastauthor',
        0x09:'Revnumber',
        0x12:'Appname',
        0x0A:'Total_edittime',
        0x0B:'Lastprinted',
        0x0C:'Created',
        0x0D:'Lastsaved',
        0x0E:'Pagecount',
        0x0F:'Wordcount',
        0x10:'Charcount',
        0x13:'Security',
        0x11:'Thumbnail'
        }

class Property(SimpleStruct):
    fields=[
        [ 'Type',PropType],
        [ 'Offset',LONG], #This is relative to the section
        ]

class PropArray(ARRAY):
    target_class=Property

def parse_summary_info(p,file):
    ## Get the property stream
    data = file.cat(p)
    header = PropHeader(data)

    fd = cStringIO.StringIO(data[header.size():])

    ## A FIDAndOffsetArray tells us where all the property sections are
    fids = FIDAndOffsetArray(Buffer(fd=fd),count=header['cSections'])

    for fid in fids:
        offset=fid['offset'].get_value()

        ## Lets grab each section:
        section_data = data[offset:]
        section=DataSize(section_data)
        
        ## Now we know how many properties there are
        props = PropArray(section_data[section.size():],
                          count=section['cProps'].get_value())
        
        ## Lets grab each property
        for prop in props:
            offset=prop['Offset'].get_value()
            ## This is an enum based on a long - This looks up the
            ## right type based on the value in the long
            value = PropDataType(section_data[offset:])
            try:
                cls=value.get_value()
                ## We recognise this data type - Lets get it
                if issubclass(cls,DataType):
                    v=cls(section_data[offset+value.size():])
                    ## Print the data according to its data type
                    yield (prop['Type'].get_value(),v)
            except (TypeError,KeyError),e:
                #print "Cant handle property type %s for %s" % (cls,prop['Type'])
                pass


dispatch = {
    "__substg1.0": mesg_property,
    "__attach_version1.0":mesg_attach,
    "__recip_version1.0":mesg_receipt,
    "SummaryInformation":parse_summary_info,
    }

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    a=OLEFile(Buffer(fd=fd))
    for p in a.properties:
        for i in dispatch.keys():
            property_name = p['pps_rawname'].__str__()
            if re.search(i,property_name):
                for prop,value in dispatch[i](p,a):
                    print "%s: %s" % (prop,value)
