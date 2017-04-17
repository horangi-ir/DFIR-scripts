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
        # if args.extract == True:
        #       if not os.path.exists(outputPath):
        #         os.makedirs(outputPath)
        #       extractFile = open(outputPath+entryObject.info.name.name,'w')
        while offset < entryObject.info.meta.size:
            available_to_read = min(BUFF_SIZE, entryObject.info.meta.size - offset)
            filedata = entryObject.read_random(offset,available_to_read)
            md5hash.update(filedata)
            sha1hash.update(filedata)
            offset += len(filedata)
        #     if args.extract == True:
        #       extractFile.write(filedata)
        #
        # if args.extract == True:
        #     extractFile.close
        print "shoud be writing " + entryObject.info.name.name
        hashOutput.writerow([int(entryObject.info.meta.addr),'/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),md5hash.hexdigest(),sha1hash.hexdigest()])
    elif f_type == pytsk3.TSK_FS_NAME_TYPE_REG and entryObject.info.meta.size == 0:
        hashOutput.writerow([int(entryObject.info.meta.addr),'/'.join(parentPath)+entryObject.info.name.name,datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),datetime.datetime.fromtimestamp(entryObject.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),int(entryObject.info.meta.size),"d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709"])

    else:
      pass
          # print "This went wrong",entryObject.info.name.name,f_type


def collectFromDisk(imagehandle,output):
    
    """CollectFromDisk is designed to extract a predefined set of files from a disk image or live disk.
    It makes heavy use of the pytsk3 library to mount the image, identify files, and move them to a
    specified output directory.

    collectFromDisk currently takes 5 arguments, the imagefile in question, the output directory, a list
    of files to collect, and a list of full directories to collect. It is possible to include the root
    directory and export every file in the directory structure, however this is likely very time consuming.
    """

    #imagehandle = pytsk3.Img_Info(imagefile) #Img_Info opens and stores general information about a disk
    partitionTable = pytsk3.Volume_Info(imagehandle) #The partition table is returned from the Volume_Info function
    print partitionTable
    """
    **This may not be entirely accurate and I need to do more research, but it's the basic idea.

    the following for loop iterates through each element in 'partitionTable'. If 'Basic' or 'NTFS' is found
    a predefined set of files are extracted and written to the output director. Older disks with smaller partitions
    normally have an Master File Table (MFT). The Partition table within the MFT typically contains the string
    'NTFS' for NTFS formated partitions. However newer drives with a GUID Partition Table (GPT) usally contain the
    strings 'Basic File System' for NTFS formated partition. As a result, both strings are included.
    """
    for partition in partitionTable:
      print partition.addr, partition.desc, "%ss(%s)" % (partition.start, partition.start * 512), partition.len
      if 'Basic data partition' or 'NTFS' in partition.desc:
        try:
            """
            This loop iterates through the list of files specified for acquisition. This loop assumes that 'files'
            is formated in a specific fashion. That is, it's a python dictionary that contains the name of the evidence type
            (registry, event logs, email archive, etc) and the file's path. e.g.

                    {"name":"Registry","path":"/Windows/System32/config/SYSTEM"}
            """
            for entry in files:
                path = entry["path"]
                try:
                    """
                    if I'm not mistaiken, the filesystemObject in this case is the logical partition. It is mounted here
                    so that we can look for specific files by their path.
                    """
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))

                    fileobject = filesystemObject.open(path)


                    # I normally print the following items for debugging purposes.
                    """
                    #print path
                    #print "File Inode:",fileobject.info.meta.addr
                    #print "File Name:",fileobject.info.name.name
                    #print "File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S')
                    """

                    """
                    If the specified output directory doesn't already exist, this creates the output directory based on the hostname.
                    """

                    outdir = output+"/"+entry["name"]
                    if not os.path.exists(outdir): os.makedirs(outdir)

                    """
                    the outFileName takes the file name of the file specified in the list of target evidence files and
                    prepends a bunch of stuff to look like this:

                    <output directory>/<system name>/<file name>.


                    """
                    outFileName = output+"/"+entry["name"]+ "/" +str(partition.addr)+" "+fileobject.info.name.name

                    """
                    This writes the evidence file to disk
                    """
                    outfile = open(outFileName, 'w')
                    filedata = fileobject.read_random(0,fileobject.info.meta.size)
                    outfile.write(filedata)
                    outfile.close

                #here we have some terrible exception handling with no descriptions of what is going on.

                except:

                    pass
            """
            #This does exactly the same as above, execpt for a list of directories. It recursively copies every
            #file in the directory and its subdirectories to a specified output directory.
            """
            for entry in directories:
                directory = entry["path"]

                try:
                    filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start*512))
                    directoryObject = filesystemObject.open_dir(directory)
                    for entryObject in directoryObject:
                        if entryObject.info.name.name in [".", ".."]:
                            continue

                        filepath =(directory+"/"+entryObject.info.name.name)
                        #print output
                        #print directory, entryObject.info.name.name
                        #print filepath

                        fileobject = filesystemObject.open(filepath)
                        #print "File Inode:",fileobject.info.meta.addr
                        #print "File Name:",fileobject.info.name.name
                        #print "File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S')
                        outFileName = output+"/"+entry["name"]+"/"+str(partition.addr)+" "+fileobject.info.name.name
                        outdir = output+"/"+entry["name"]
                        if not os.path.exists(outdir): os.makedirs(outdir)
                        #print outFileName
                        outfile = open(outFileName, 'w')
                        filedata = fileobject.read_random(0,fileobject.info.meta.size)
                        outfile.write(filedata)
                        outfile.close
                except:
                    pass
        except:
            pass




