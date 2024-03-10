import csv
import shutil
import os

def get_Packed_File_List():
    packed_File_List_File = open('./data_info/dynamic_Data.csv', 'r', encoding='UTF-8')
    packed_File_List = csv.reader(packed_File_List_File)

    packed_File_List_Name = []

    for data in packed_File_List:
        packed_File_List_Name.append(data[0].split('.vir')[0])

    packed_File_List_File.close()

    return packed_File_List_Name

def extractedFile_Classfication():
    packed_File_List_Name = get_Packed_File_List()
    extracted_File_List = os.listdir('C:/Users/ucloud/Desktop/extracted Data/')

    for extracted_File in extracted_File_List:
        if extracted_File.split('.json')[0] not in packed_File_List_Name:
            shutil.move('C:/Users/ucloud/Desktop/extracted Data/' + extracted_File, 'C:/Users/ucloud/Desktop/data/' + extracted_File)

def get_Non_existent_File():
    packed_File_List_Name = get_Packed_File_List()
    extracted_File_List = os.listdir('C:/Users/ucloud/Desktop/extracted Data/')
    extracted_File_List_Name =[]
    non_Extracted_File_List = []

    for extracted_File in extracted_File_List:
        extracted_File_List_Name.append(extracted_File.split('.json')[0])

    for packed_File in packed_File_List_Name:
        if packed_File not in extracted_File_List_Name:
            non_Extracted_File_List.append(packed_File)

    write_File = open('C:/Users/ucloud/Desktop/non_extracted_file_2.csv', 'w', encoding='utf-8')

    for value in non_Extracted_File_List:
        write_File.write(value + '\n')

    write_File.close()

def __main__():
    extractedFile_Classfication()
    get_Non_existent_File()

__main__()
