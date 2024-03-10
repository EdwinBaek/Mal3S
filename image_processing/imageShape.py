import os
import csv
import numpy as np
import pandas as pd
from PIL import Image

def getImageSize():
    benign_Image_Path = './Benign_Image/'
    malware_Image_Path = './Malware_Image/'

    benign_Image_List = os.listdir(benign_Image_Path)
    malware_Image_List = os.listdir(malware_Image_Path)

    width = 0       # Image width
    height = 0      # Image height
    depth = 3       # Fixed size to 3
    box_0_name = '' # Benign or Malware
    box_0_xmin = 0  # Fixed size to 0
    box_0_ymin = 0  # Fixed size to 0
    box_0_xmax = 0  # Fixed to width size
    box_0_ymax = 0  # Fixed to height size
    num_obj = 0     # Count of number of image files
    fileId = ''     # Image file name
    count = 0       # Count operation variable

    info_List = []

    for image in benign_Image_List:
        count += 1

        im = Image.open(benign_Image_Path + image)

        width = im.size[0]
        height = im.size[1]
        depth = 3
        box_0_name = 'benign'
        box_0_xmin = 0
        box_0_ymin = 0
        box_0_xmax = width
        box_0_ymax = height
        num_obj = count
        fileId = image.split('.json.csv.csv.png')[0]

        info_List.append([width, height, depth, box_0_name, box_0_xmin, box_0_ymin, box_0_xmax, box_0_ymax, num_obj, fileId])

    for image in malware_Image_List:
        count += 1

        im = Image.open(malware_Image_Path + image)

        width = im.size[0]
        height = im.size[1]
        depth = 3
        box_0_name = 'malware'
        box_0_xmin = 0
        box_0_ymin = 0
        box_0_xmax = width
        box_0_ymax = height
        num_obj = count
        fileId = image.split('.json.csv.csv.png')[0]

        info_List.append([width, height, depth, box_0_name, box_0_xmin, box_0_ymin, box_0_xmax, box_0_ymax, num_obj, fileId])

    # Data Save
    f = open('./SPP_Input_Data/SPP_Input.csv', 'w', newline='', encoding='utf-8')
    wr = csv.writer(f)
    for value in info_List:
        wr.writerow(value)
    f.close()

def makeShape():
    image_Dict = dict()
    total_Image_Info_List = []
    SPP_Input_File_Path = './SPP_Input_Data/SPP_Input.csv'
    dict_Keys = ['width', 'height', 'depth', 'box_0_name', 'box_0_xmin', 'box_0_ymin', 'box_0_xmax', 'box_0_ymax', 'num_obj', 'fileId']

    with open(SPP_Input_File_Path, mode='r') as file:
        reader = csv.reader(file)
        for value in reader:
            for index in range(0, len(dict_Keys)):
                image_Dict[dict_Keys[index]] = value[index]
            total_Image_Info_List.append(image_Dict)
            image_Dict = {}
    # print(total_Image_Info_List)

    return total_Image_Info_List


def main():
    getImageSize()
    total_Image_Info_List = makeShape()
    # makeDF(total_Image_Info_List)

main()