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
import time
from socket import gethostname
import ntpath
from os.path import basename
import subprocess
from collectors import *
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
        self.extractFromDisk = False
        self.getHashList = False
        self.antivirus = True

    def output(self,imagefile):
        if imagefile != None:
            output = self.outpath +"/"+ os.path.basename(imagefile)
            hashOutput = self.outpath +"/" +os.path.basename(imagefile) +"/"+ os.path.basename(output) +"_Hash_List" +".csv"
            clamlog = self.outpath +"/" +os.path.basename(imagefile) +"/"+ os.path.basename(output) +"_clamscan_log" +".txt"
            malwareDir = self.outpath +"/" +os.path.basename(imagefile)  +"/malware"

        else:
            output = self.outpath

        return output, hashOutput, clamlog, malwareDir

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

                if self.antivirus == True:
                    if not os.path.exists(self.output(imagefile)[3]): os.makedirs(self.output(imagefile)[3])
                    clamCommand = str("clamscan -r --log="+ self.output(imagefile)[2] +" --copy="+ self.output(imagefile)[3] +" --verbose /mnt/windows")
                    print clamCommand
                    # self.mount(imagefile,partition)
                    # subprocess.call(clamCommand,shell=True)
                    # time.sleep(15)
                    # self.umount()

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

    def mount(self,imagefile,partition):
        

        mountCommand = "mount -o loop,ro,no_exec,show_sys_files,offset=32256"

        if "Win95" in partition.desc:
            mountCommand = "mount -o loop,ro,offset=32256"

        ewfDir = "/mnt/ewf"
        ewfFile = "/mnt/ewf/ewf1"
        mountDir = "/mnt/windows"
        mountCommand += " " + ewfFile + " " + mountDir
        ewfMount = "ewfmount " +imagefile + " " + ewfDir

        print "print executing ewfmount"
        print ewfMount + "\n"
        subprocess.call(ewfMount, shell=True)
    
        # time.sleep(5)
        print "print executing mount"
        print mountCommand + "\n"
        subprocess.call(mountCommand, shell=True)
    
    def umount(self):
        
        ewfDir = "umount /mnt/ewf"
        mountDir = "umount /mnt/windows"


        print "executing umount on /mnt/windows"
        subprocess.call(mountDir, shell=True)
        time.sleep(3)
        print "executing umount on /mnt/ewf"
        subprocess.call(ewfDir, shell=True)

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
    
