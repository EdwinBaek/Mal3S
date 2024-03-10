import csv
import os
import shutil

def findCopyFile(fileInfo_Path, criteria):
    copiedFileList = []

    file_Info_File = open(fileInfo_Path, 'r', encoding='utf-8')
    file_Info = csv.reader(file_Info_File)

    for data in file_Info:
        if data[3] < criteria:
            copiedFileList.append(data[0])

    return copiedFileList

def copy(original_Path, destination_Path, copiedFileList):
    for file in copiedFileList:
        shutil.copyfile(os.path.join(original_Path, file), os.path.join(destination_Path, file))

def __main__():
    copiedFileList = findCopyFile('c:/Users/JBH/Desktop/zero_entropy_list.csv', 6.8)
    copy('c:/Users/JBH/Desktop/dataset/', 'c:/Users/JBH/Desktop/6dot8/', copiedFileList)

__main__()