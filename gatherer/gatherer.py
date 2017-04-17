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
        self.getHashList = True
        self.antivirus = False
        self.extract = False


    def output(self):
        if self.imagefile != None:
            output = self.outpath +"/"+ os.path.basename(self.imagefile)
        
        else:
            output = self.outpath

        return output

    def readImageFile(self,imagefile):
        filenames = pyewf.glob(imagefile)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        imagehandle = ewf_Img_Info(ewf_handle)

        partitionTable = pytsk3.Volume_Info(imagehandle)

        return partitionTable, imagehandle

    def analysis(self):

        partitionTable, imagehandle = self.readImageFile(self.imagefile)

        for partition in partitionTable:
            print partition.desc
            if 'NTFS' in partition.desc or 'Basic data partition' in partition.desc or 'Win95 FAT32' in partition.desc:
                if self.getHashList == True:
                    self.hashList(partition,imagehandle)



    def hashList(self,partition, imagehandle):
        output = self.output()
        if not os.path.exists(output): os.makedirs(output)
        output = output + "/"+os.path.basename(output)+"_Hash_List_Partition_" + str(partition.addr) +".csv"
        print output
        # outfile = open(output,'wb')
        # outfile.write('"Inode","Full Path","Creation Time","Modified Time","Accessed Time","Size","MD5 Hash","SHA1 Hash"\n')
        # global wr
        # wr = csv.writer(outfile, quoting=csv.QUOTE_ALL)

        # for partition in iPartitions:
        #     filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
        #     directoryObject = filesystemObject.open_dir(path=dirPath)
        #     print "Directory:",dirPath
        #     directoryRecurse(directoryObject,[])


if __name__ == "__main__":

    disk1 = investigation()
    disk1.analysis()
    # timeline(mount(args.imagefile,"/"),output(),)
    
