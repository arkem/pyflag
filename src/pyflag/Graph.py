#!/usr/bin/env python
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

""" Graph UI implementations.

The Abstract base class must be extended for implementation of graph drawing. Reports may call this class in order to draw a graph. By calling the UI's graph method this graph may be installed properly within the UI """

import pyflag.conf
config=pyflag.conf.ConfObject()
import re,cStringIO

config.add_option("IMAGEDIR", default=config.DATADIR + "/images/",
                  help="Directory for all images/thumbnails")

import os,pipes

class GraphException(Exception): pass

class Image:
    """ Class defining the Image Interface.

    Note that this class implements a very simple image interface. The only requirements on this interface is that there are the following methods:

    >>>  def GetContentType(self)
    >>>  def SetFormat(self,format)
    >>>  def display(self)
    """
    out_format = 'png'

    def __init__(self,data):
        self.data=data

    def GetContentType(self):
        """ This should produce the proper mime-type for this image class.

        The default implementation uses magic to determine the content type. This is sufficiently intelligent for most applications. The only reason you might want to override this is if the extra overhead of displaying the image twice is too prohibitive.
        """
        import pyflag.Magic as Magic

        magic = Magic.MagicResolver()
        return magic.estimate_type(self.display(), None, None)[0][1].mime_str()
    
    def SetFormat(self,format):
        """ A function used to set the output format.

        The caller specifies the format the image is requested in. If the implementation can not produce output in this format, the best format prefered by the implementation is returned, otherwise the requested format is returned.
        
        @arg format: Requested format.
        @return: Best format prefered by the implementation, or the requested format if available """
        self.out_format = format
        return format
        
    def display(self):
        """ Displays the image in the format specified in out_format if possible.

        @return: A binary string representing the image in its requested format.
        """
        return self.data

class GenericGraph:
    """ Abstract class defining the graph interface.
    """

    def form(self, query, result):
        """ A configuration form we will draw to allow the user to
        adjust the plot
        """
    
    def plot(self, gen, query, result):
        """ This is the main interface for the plotting engine.

        Given a generator in gen which produces a sequence of dicts.
        The columns specify the elements of each dict to be drawn 

        we will draw on result a graph.
        """
        ## The default graph is just a list
        for x in gen:
            result.row(*x)

Graph = GenericGraph

## We use the python imaging library to manipulate all the images:
import PIL.Image

class Thumbnailer(Image):
    """ An image class to display thumbnails files.
    
    This object is derived from the Image class, and knows how to create thumbnails of itself.
    Any type of object may be stored here and used in the UI.image method. The content type will be deduced automatically using magic.

    If you want to teach this object how to create more thumbnails, add more methods and update the dispatcher accordingly.

    @cvar dispatcher: A dictionary that manages access to the different thumbnail creation routines. The keys should be the relevant mime type, while the values are the string name of the method.
    """
    def __init__(self,fd,size_x):
        """ fd is the image, size_x is the requested width of the image. The height will be calculated to preserve aspect ratio """
        self.size_x = size_x
        self.fd = fd
        self.width = 0
        self.height = 0

        ## Calculate the magic of this file:
        import pyflag.Magic as Magic

        magic = Magic.MagicResolver()
        self.magic, self.content_type = magic.find_inode_magic(self.fd.case,
                                                               inode_id = self.fd.lookup_id())

        ## Now use the magic to dispatch the correct handler:
        ## Use the content type to access the thumbnail
        try:
            method=getattr(self,self.dispatcher[self.content_type])
        except KeyError,e:
            self.Unknown()
            return

        try:
            method()
        except IOError: pass

        ## Note that handler are expected to set
        ## self.width,self.height as well as self.thumbnail which
        ## should be a generator to generate the thumbnail

    def set_image(self,name):
        """ Sets the thumbnail to a constant image """
        self.image = PIL.Image.open(os.path.join(config.IMAGEDIR,name))
        self.width, self.height = self.image.size
        self.thumbnail = open(os.path.join(config.IMAGEDIR,name),'rb')
        self.content_type='image/png'
        
    def Unknown(self):
        """ Default handler """
        return self.set_image("unknown.png")

    def PDFHandler(self):
        """ Handle PDF Documents """
        return self.set_image("pdf.png")
    
    def MSOffice(self):
        """ Handle MSOffice Documents """
        return self.set_image("msoffice.png")

##    def MpegHandler(self):
##        """ Perform Video Thumbnailing with mplayer """

##        # try to create thumbnail
##        try:
##            mplayer = os.popen('cd /tmp; mplayer -vo png -ao null -frames 1 -', 'w')
##            mplayer.write(self.Extract_size(1000000))
##            mplayer.close()
##        except IOError:
##            pass

##        try:
##            # see if the thumb was created
##            fd = open('/tmp/00000001.png')
##            result = fd.read()
##            fd.close()
##            try:
##                import glob
##                for i in glob.glob('/tmp/000*.png'):
##                    os.remove(i)
##            except OSError, e:
##                pass
##            self.content_type='image/png'
##            return result
##        except (IOError,OSError), e:
##            return self.set_image("broken.png")
        
    def JpegHandler(self):
        """ Handles Jpeg thumbnails.
        """
        ## Calculate some basic statistics
        self.fd.seek(0)
        fd = cStringIO.StringIO(self.fd.read(2000000) + "\xff\xd9")

        try:
            self.image = PIL.Image.open(fd)
        except Exception,e:
            print "PIL Exception %s" % e
            self.size_x=24
            self.set_image("no.png")
            return
        
        ## Ask the imaging library to rescale us to the requested size:
        self.width, self.height = self.image.size
        self.owidth, self.oheight = self.image.size

        ## Calculate the ratio
        if self.width > self.height:
            dimensions = ( self.size_x, int(self.size_x * self.height / self.width))
        else:
            dimensions = ( int(self.size_x * self.width / self.height), self.size_x)

        self.thumbnail = cStringIO.StringIO()
        try:
            self.image.thumbnail(dimensions, PIL.Image.NEAREST)
        except Exception,e:
            print e

        try:
            self.image.save(self.thumbnail,self.image.format)
            self.thumbnail.seek(0)
            self.width, self.height = self.image.size
        except:
            self.size_x=24
            self.set_image("no.png")
        

    def Null(self):
        """ A do nothing method that just returns the original image as its thumbnail. """
        self.thumbnail = self.fd
        
    dispatcher ={"image/jpg":"JpegHandler","image/jpeg":"JpegHandler",
                 "image/png":"JpegHandler","image/gif":"JpegHandler",
# commented out mplayer stuff cos its kinda slow, cool but...
#                 "video/mpeg":"MpegHandler","video/x-msvideo":"MpegHandler",
#                 "video/x-ms-asf":"MpegHandler",
                 "application/pdf":"PDFHandler",
#                 "video/quicktime":"MpegHandler",
                 "application/msword":"MSOffice",
		 "application/msaccess":"MSOffice",
                 }    

    def display(self):
        ## Maximum length to read:
        return self.thumbnail.read(2000000)

    def GetMagic(self):
        return self.magic

    def GetContentType(self):
        return self.content_type

    def SetFormat(self,format):
        """ We only support jpeg here """
        return 'jpeg'
