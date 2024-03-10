import csv
import os

def checkPackedFile(input_File_Path, output_File_Path, criteria):
    input_Data_File = open(input_File_Path, 'r', encoding='utf-8')
    input_Data = csv.reader(input_Data_File)

    output_Data = []

    for data in input_Data:
        if data[2] == criteria:
            output_Data.append([data[0], data[1]])

    output_Data_File = open(output_File_Path, 'w', newline='', encoding='utf-8')
    output_wr = csv.writer(output_Data_File)

    for data in output_Data:
        output_wr.writerow(data)

    input_Data_File.close()
    output_Data_File.close()

    print(criteria + ' Data size : ' + str(len(output_Data)))

def getOverlapFile(extracted_File_Path, packed_File_Path):
    extracted_File_List = os.listdir(extracted_File_Path)
    extracted_Data = []
    for data in extracted_File_List:
        extracted_Data.append(data.split('.json')[0])

    packed_Data_File = open(packed_File_Path, 'r', encoding='utf-8')
    packed_Data = []
    for data in packed_Data_File:
        packed_Data.append(data.split('.vir')[0])

    packed_Data_File.close()

    count = 0
    for extract in extracted_Data:
        if extract in packed_Data:
            count += 1

    print('Number of extracted file : ' + str(len(extracted_Data)))
    print('Number of packed file : ' + str(len(packed_Data)))
    print('Number of overlaps : ' + str(count))


def dynamicDataCheck(dynamic_File_Path, extracted_Data_File_Path, output_File_Path):
    '''
    The output value is the name of the dynamic data file that was not extracted.
    '''

    dynamic_Data_File = open(dynamic_File_Path, 'r', encoding='utf-8')
    dynamic_Data = csv.reader(dynamic_Data_File)

    extracted_Data = os.listdir(extracted_Data_File_Path)

    dynamic_Data_Name_List = []
    for data in dynamic_Data:
        dynamic_Data_Name_List.append(data[0])

    output_Data = []

    for extract in extracted_Data:
        if extract not in dynamic_Data_Name_List:
            output_Data.append(extract)

    output_Data_File = open(output_File_Path, 'w', newline='', encoding='utf-8')
    output_wr = csv.writer(output_Data_File)

    for data in output_Data:
        output_wr.writerow(data)

    dynamic_Data_File.close()
    extracted_Data.close()
    output_Data_File.close()


def main():
    # checkPackedFile('./Z_file_Information/Total_File_Infor.csv', './Z_file_Information/Dynamic_Data.csv', 'Packed')
    # checkPackedFile('./Z_file_Information/Total_File_Infor.csv', './Z_file_Information/Static_Data.csv', 'Unpacked')
    getOverlapFile('D:/final_reports/', 'C:/Users/Desktop/Packing_Check_Data/packingData_6dot8.csv')
    # dynamicDataCheck('./Z_file_Information/Dynamic_Data.csv', './Z_file_Information/Extracted_Data.csv', './Z_file_Information/Check_Dynamic_Data.csv')

main()
