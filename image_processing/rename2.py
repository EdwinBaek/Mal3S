import os
from os import rename
import json
import csv
count = 1

name = [3,15,30,44,49,58,60,64,66,95,115,120,140,165,167,176,181,182,195,196,202,227,241,247,275,279,290,296,315,332,342,360]

# for dir_List in dir:
file_Path = 'C:/Users/Desktop/test/'
file_Name = ''

file_list = os.listdir(file_Path)


for file in file_list:
    rename(file_Path+file, file_Path+ str(count) +'.jpg')

    # rename(file_Path+file, file_Path+ str(name[count]) +'.jpg')
    count += 1

