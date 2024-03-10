import csv

def rewrite(input_Data_File_Path, output_Data_File_Path, criteria):
    input_Data_File = open(input_Data_File_Path, 'r', encoding='utf-8')
    input_Data = csv.reader(input_Data_File)

    output_Data = []

    for data in input_Data:
        if float(data[2]) >= criteria:
            output_Data.append([data[0], "Packed", data[2]])
        else:
            output_Data.append([data[0], "Unpacked", data[2]])

    output_Data_File = open(output_Data_File_Path, 'w', newline='', encoding='utf-8')
    output_wr = csv.writer(output_Data_File)

    for data in output_Data:
        output_wr.writerow(data)

    input_Data_File.close()
    output_Data_File.close()

def main():
    packingData_File_Path = 'C:/Users/ucloud/Desktop/Packing_Check_Data/packingData.csv'
    packing_Data_6dot8_Path = 'C:/Users/ucloud/Desktop/Packing_Check_Data/packingData_6dot8.csv'
    packing_Data_7_Path = 'C:/Users/ucloud/Desktop/Packing_Check_Data/packingData_7.csv'
    packing_Data_7dot2_Path = 'C:/Users/ucloud/Desktop/Packing_Check_Data/packingData_7dot2.csv'

    rewrite(packingData_File_Path, packing_Data_6dot8_Path, 6.8)
    rewrite(packingData_File_Path, packing_Data_7_Path, 7.0)
    rewrite(packingData_File_Path, packing_Data_7dot2_Path, 7.2)

main()