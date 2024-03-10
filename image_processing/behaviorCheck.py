import json
import os

file_path = 'C:/Users/ucloud/Desktop/extracted Data/'
report_dir = os.listdir(file_path)

non_extracted_File_List = []
count = 0
for file in report_dir:
    report_file = open(file_path + str(file), 'r')
    report_data = json.load(report_file)

    if 'behavior' not in report_data:
        print('count = %d -- file name : %s >>>>>>>> non behavior' % (count, file))
        non_extracted_File_List.append(file)
    else:
        if 'processes' not in report_data['behavior']:
            non_extracted_File_List.append(file)
            print('count = %d -- file name : %s  >>>>>>>> non behavior - processes' % (count, file))
        else:
            print('count = %d -- processes exist' % (count))

    count += 1

    report_file.close()
    # print(non_extracted_File_List)

f = open('C:/Users/ucloud/Desktop/re_extract_File_List.csv', 'w', encoding='utf-8')

for value in non_extracted_File_List:
    f.write(value + '\n')

f.close()
