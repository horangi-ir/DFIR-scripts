__author__ = 'spydir'
import pytsk3
import datetime
import json
import csv
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
import ntpath
from os.path import basename
from artifacts import files
import pyclamd

def hashList(output, entryObject, parentPath,hashOutput):
    # if self.getHashList == True:
    

    # output = output + "/"+ os.path.basename(output) +"_Hash_List_Partition_" +".csv"
    # outfile = open(output,'wb')
    # outfile.write('"Inode","Full Path","Creation Time","Modified Time","Accessed Time","Size","MD5 Hash","SHA1 Hash"\n')
    # hashOutput = csv.writer(outfile, quoting=csv.QUOTE_ALL)

    if entryObject.info.meta.size != 0:
        # print entryObject.info.name.name
        # print "File:",parentPath,entryObject.info.name.name,entryObject.info.meta.size
        BUFF_SIZE = 1024 * 1024
        offset=0
        md5hash = hashlib.md5()
        sha1hash = hashlib.sha1()
        sha256hash = hashlib.sha256()

        while offset < entryObject.info.meta.size:

            try: 
                # with Timeout(3):
                    # print "Reading File Data"   
                    available_to_read = min(BUFF_SIZE, entryObject.info.meta.size - offset)
                    filedata = entryObject.read_random(offset,available_to_read)
                    md5hash.update(filedata)
                    sha1hash.update(filedata)
                    sha256hash.update(filedata)
                    if len(filedata) == 0:
                        offset = entryObject.info.meta.size +1
                    else: 
                        offset += len(filedata)
  

            except:
            # except Timeout.Timeout:
                # print "Timeout: ", filepath
                pass

        # if args.extract == True:
        #    extractFile.write(filedata)
        #
        # if args.extract == True:
        #    extractFile.close

        hashOutput.writerow([int(entryObject.info.meta.addr),'/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),md5hash.hexdigest(),sha1hash.hexdigest(),sha256hash.hexdigest()])
    elif entryObject.info.meta.size == 0:
        hashOutput.writerow([int(entryObject.info.meta.addr),'/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),"d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])

    else:
      pass
          # print "This went wrong",entryObject.info.name.name,f_type

def extractFromDisk(imagehandle,partition,output):
    
    # partitionTable = pytsk3.Volume_Info(imagehandle) #The partition table is returned from the Volume_Info function
    # print partitionTable

    # for partition in partitionTable:
      print partition.addr, partition.desc, "%ss(%s)" % (partition.start, partition.start * 512), partition.len
      if 'Basic data partition' or 'NTFS' in partition.desc:
        try:
            for entry in files:
                path = entry["path"]
                try:
                    
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))

                    fileobject = filesystemObject.open(path)

                    outdir = output+"/"+entry["name"]
                    if not os.path.exists(outdir): os.makedirs(outdir)

                    outFileName = output+"/"+entry["name"]+ "/" +str(partition.addr)+" "+fileobject.info.name.name

                    outfile = open(outFileName, 'w')
                    filedata = fileobject.read_random(0,fileobject.info.meta.size)
                    outfile.write(filedata)
                    outfile.close

                except:

                    pass
           
            for entry in directories:
                directory = entry["path"]

                try:
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    directoryObject = filesystemObject.open_dir(directory)
                    for entryObject in directoryObject:
                        if entryObject.info.name.name in [".", ".."]:
                            continue

                        filepath =(directory+"/"+entryObject.info.name.name)

                        fileobject = filesystemObject.open(filepath)
                        outFileName = output+"/"+entry["name"]+"/"+str(partition.addr)+" "+fileobject.info.name.name
                        outdir = output+"/"+entry["name"]
                        if not os.path.exists(outdir): os.makedirs(outdir)
                        
                        outfile = open(outFileName, 'w')
                        filedata = fileobject.read_random(0,fileobject.info.meta.size)
                        outfile.write(filedata)
                        outfile.close
                except:
                    pass
        except:
            pass

def clamAV(mountDir):
    cd = pyclamd.ClamdAgnostic()
    for root, dirs, files in os.walk(mountDir):
        for name in files:
            if os.path.isfile(os.path.join(root,name)):
                result = cd.scan_file(os.path.join(root,name))
                print result

    pass


