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
from socket import gethostname
import ntpath
from os.path import basename
from collectors import *
from timeout import Timeout
import signal



argparser = argparse.ArgumentParser(description='Hash files recursively from all NTFS parititions in a live system and optionally extract them')

argparser.add_argument(
        '-i', '--image',
        dest='imagefile',
        action="store",
        type=str,
        default=None,
        required=False,
        help='E01 to extract from')

argparser.add_argument(
        '-o', '--output',
        dest='output',
        action="store",
        type=str,
        default='inventory.csv',
        required=True,
        help='File to write the hashes to')

args = argparser.parse_args()


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

        self.evidenceDir = args.imagefile
        self.outpath = args.output
        self.extractFromDisk = True
        self.getHashList = True
        self.antivirus = False


    def output(self,imagefile):
        if imagefile != None:
            output = self.outpath +"/"+ os.path.basename(imagefile)
            hashOutput = self.outpath +"/" +os.path.basename(imagefile) +"/"+ os.path.basename(output) +"_Hash_List" +".csv"
        
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

    def analysis(self, dirPath, imagefile):

        partitionTable, imagehandle = self.readImageFile(imagefile)

        for partition in partitionTable:
            print partition.desc
            if 'NTFS' in partition.desc or 'Basic data partition' in partition.desc or 'Win95 FAT32' in partition.desc:

                if self.extractFromDisk == True:
                    extractFromDisk(imagehandle,partition,self.output(imagefile)[0])

                if self.getHashList == True:
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    directoryObject = filesystemObject.open_dir(path=dirPath)
                    print "Directory:",dirPath
                    if not os.path.exists(self.output(imagefile)[0]): os.makedirs(self.output(imagefile)[0])
                    outfile = open(self.output(imagefile)[1],'wb')
                    outfile.write('"Inode","Full Path","Creation Time","Modified Time","Accessed Time","Size","MD5 Hash","SHA1 Hash","SHA256 HASH"\n')
                    hashOutput = csv.writer(outfile, quoting=csv.QUOTE_ALL)
                    self.directoryRecurse(directoryObject,[],hashOutput,imagefile)

    def directoryRecurse(self,directoryObject, parentPath, hashOutput,imagefile):

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
                        self.directoryRecurse(sub_directory,parentPath,hashOutput,imagefile)
                        parentPath.pop(-1)
                        # print "Leaving Directory: %s" % filepath


                    elif f_type == pytsk3.TSK_FS_NAME_TYPE_REG and entryObject.info.name.name.lower().endswith((".exe",".dll")):
                        
                        # print entryObject.info.name.name
                        try: 
                                
                                print "Hashing: ", filepath
                                hashList(self.output(imagefile), entryObject, parentPath,hashOutput)
                        
                        except:
                            continue
 

                except IOError as e:
                    #print e
                    continue

def findDisks():
    disks = []
    for root, dirs, files in os.walk(args.imagefile):
        for name in files:
            if name.endswith((".E01")):
                if os.path.isfile(os.path.join(root,name)):
                    if "RECYCLE" not in os.path.join(root,name):
                        disks.append(os.path.join(root,name))
    return disks

if __name__ == "__main__":

    # disk1 = investigation()
    # disk1.findDisks()
    for index,item in enumerate(findDisks()):
        index = investigation()
        index.analysis("/", item)

    # disk1.analysis("/")
    
