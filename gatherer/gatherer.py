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

def mount(imagefile,dirPath):
    iPartitions = []

    filenames = pyewf.glob(imagefile)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)
    imagehandle = ewf_Img_Info(ewf_handle)

    partitionTable = pytsk3.Volume_Info(imagehandle)
    for partition in partitionTable:
      print partition.desc
      if 'NTFS' in partition.desc  or 'Basic data partition' in partition.desc:
        iPartitions.append(partition)

    return iPartitions, imagehandle, dirPath

def output():
    if args.imagefile != None:
        output = args.output +"/"+ ntpath.basename(args.imagefile)

    else:
        output = args.output

    return output

if __name__ == "__main__":

    #collectFromDisk(mount(),output())
    # print mount(args.imagefile,"/")
    timeline(mount(args.imagefile,"/"),output(),)
    
