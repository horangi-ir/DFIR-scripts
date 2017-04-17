#!/usr/bin/python
# Sample program or step 11 in becoming a DFIR Wizard!
# No license as this code is simple and free!
import sys
import pytsk3
import datetime
import pyewf
import argparse
import hashlib
import csv
import os
import re
import psutil
import signal
import time
from socket import gethostname
import ntpath
from os.path import basename
from collectors import *

argparser = argparse.ArgumentParser(description='Hash files recursively from all NTFS parititions in a live system and optionally extract them')

argparser.add_argument(
        '-i', '--image',
        dest='imagefile',
        action="store",
        type=str,
        default=None,
        required=False,
        help='E01 to extract from'
    )

argparser.add_argument(
        '-o', '--output',
        dest='output',
        action="store",
        type=str,
        default='inventory.csv',
        required=True,
        help='File to write the hashes to'
    )


args = argparser.parse_args()

class Timeout():
    """Timeout class using ALARM signal."""
    class Timeout(Exception):
        pass
 
    def __init__(self, sec):
        self.sec = sec
 
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)
 
    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm
 
    def raise_timeout(self, *args):
        raise Timeout.Timeout()

class ewf_Img_Info(pytsk3.Img_Info):
  def __init__(self, ewf_handle):
    self._ewf_handle = ewf_handle
    super(ewf_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._ewf_handle.close()

  def read(self, offset, size):

    self._ewf_handle.seek(offset)
    return self._ewf_handle.read(size)

  def get_size(self):
    return self._ewf_handle.get_media_size()

class investigation():
    def __init__(self):

        self.imagefile = args.imagefile
        self.outpath = args.output
        self.extractFromDisk = True
        self.getHashList = True
        self.antivirus = False
        


    def output(self):
        if self.imagefile != None:
            output = self.outpath +"/"+ os.path.basename(self.imagefile)
            hashOutput = self.outpath +"/" +os.path.basename(self.imagefile) +"/"+ os.path.basename(output) +"_Hash_List" +".csv"
        
        else:
            output = self.outpath

        return output, hashOutput

    def readImageFile(self,imagefile):
        filenames = pyewf.glob(imagefile)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        imagehandle = ewf_Img_Info(ewf_handle)

        partitionTable = pytsk3.Volume_Info(imagehandle)

        return partitionTable, imagehandle

    def analysis(self, dirPath):

        partitionTable, imagehandle = self.readImageFile(self.imagefile)

        for partition in partitionTable:
            print partition.desc
            if 'NTFS' in partition.desc or 'Basic data partition' in partition.desc or 'Win95 FAT32' in partition.desc:

                if self.extractFromDisk == True:
                    extractFromDisk(imagehandle,partition,self.output()[0])

                if self.getHashList == True:
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    directoryObject = filesystemObject.open_dir(path=dirPath)
                    print "Directory:",dirPath
                    if not os.path.exists(self.output()[0]): os.makedirs(self.output()[0])
                    outfile = open(self.output()[1],'wb')
                    outfile.write('"Inode","Full Path","Creation Time","Modified Time","Accessed Time","Size","MD5 Hash","SHA1 Hash","SHA256 HASH"\n')
                    hashOutput = csv.writer(outfile, quoting=csv.QUOTE_ALL)
                    self.directoryRecurse(directoryObject,[],hashOutput)
                


    def directoryRecurse(self,directoryObject, parentPath, hashOutput):

            search = ".*"

            for entryObject in directoryObject:
                if entryObject.info.name.name in [".", ".."]:
                    continue
                  #print entryObject.info.name.name
                try:
                    f_type = entryObject.info.name.type
                    size = entryObject.info.meta.size
                except Exception as error:
                      #print "Cannot retrieve type or size of",entryObject.info.name.name
                      #print error.message
                      continue

                try:

                    filepath = '/%s/%s' % ('/'.join(parentPath),entryObject.info.name.name)
                    outputPath ='./%s/' % ('/'.join(parentPath))

                    if f_type == pytsk3.TSK_FS_NAME_TYPE_DIR:
                        sub_directory = entryObject.as_directory()
                        # print "Entering Directory: %s" % filepath
                        parentPath.append(entryObject.info.name.name)
                        self.directoryRecurse(sub_directory,parentPath,hashOutput)
                        parentPath.pop(-1)
                        # print "Leaving Directory: %s" % filepath


                    elif f_type == pytsk3.TSK_FS_NAME_TYPE_REG and entryObject.info.name.name.lower().endswith((".exe",".dll")):
                        
                        # print entryObject.info.name.name
                        try: 
                            with Timeout(10):
                                print "Hashing: ", filepath
                                hashList(self.output(), entryObject, parentPath,hashOutput)
                        
                        except Timeout.Timeout:
                            print "Timeout: ", filepath
 

                except IOError as e:
                    #print e
                    continue

if __name__ == "__main__":

    disk1 = investigation()
    disk1.analysis("/")
    
