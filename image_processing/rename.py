import os
from os import rename
import json

# dir = os.listdir('C:/Users/ucloud/Desktop/reports/')
count = 0

# for dir_List in dir:
file_Path = 'C:/Users/ucloud/Desktop/raw data/final2/'
file_Name = ''

reports_Dir = os.listdir(file_Path)


for report in reports_Dir:
    report_File = open(file_Path + str(report), 'r', encoding='UTF-8')
    try:
        report_Data = json.load(report_File)
    except:
        print(report + ' load exception')

    try:
        extract_File_Name = report_Data['target']['file']['name']
        report_File.close()

        old_File_Name = file_Path + report
        new_file_Name = file_Path + extract_File_Name + '.json'

        rename(old_File_Name,  new_file_Name)
        print('count : ' + str(count) + '  ' + report + ' file Rename and check Success!!')
    except KeyError:
        print('count : ' + str(count) +'  file name : ' + report + ' KeyError -----> Baseline file or Error file >>>>> !!!! Need to check file type !!!!')
        report_File.close()
    except:
        print('count : ' + str(count) +'  file name : ' + report + ' execept!!')
        report_File.close()

    count += 1


