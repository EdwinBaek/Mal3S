import os
import csv
import shutil
#
# extracted_data_file_dir = os.listdir('C:/Users/ucloud/Desktop/extracted Data/')
# extracted_data_info_file_dir = os.listdir('C:/Users/ucloud/Desktop/extracted Data_info/')
#
# count = 0
# for name in extracted_data_file_dir:
#     if name.replace('.json','.json.csv') not in extracted_data_info_file_dir:
#         # shutil.move('C:/Users/ucloud/Desktop/extracted Data/' + name, 'C:/Users/ucloud/Desktop/fail extracted file/' + name)
#         count += 1
#         print(name)
#
# print(count)


image_Path = os.listdir('C:/Users/Desktop/tii_code/sppnet/image/train/')
total_Data = open('C:/Users/Desktop/tii_code/sppnet/labels/train_total.csv', 'r', encoding='utf-8')

data = csv.reader(total_Data)

check = []
for value in data:
    if value[0]+'.jpg' in image_Path:
        if value[1] == '0':
            file = value[0] + '.jpg'
            shutil.move('C:/Users/Desktop/tii_code/sppnet/image/train/' + str(file), 'C:/Users/Desktop/train_benign/' + str(file))


# print(len(os.listdir('C:/Users/ucloud/Desktop/6.8_Benign/')))

#
# file_list = os.listdir('C:/Users/Desktop/benign_691/')
#
# output_Data_File = open('C:/Users/Desktop/test_benign.csv', 'w', newline='', encoding='utf-8')
# output_wr = csv.writer(output_Data_File)
#
# for file in file_list:
#     file = file.replace('.jpg', '')
#     output_wr.writerow([file])
#


