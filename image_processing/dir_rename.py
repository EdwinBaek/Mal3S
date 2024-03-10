import os
from os import rename
import json

report_File_Dir_Path = 'D:/reports_zip/reports0/'

report_File_Dir = os.listdir(report_File_Dir_Path)

count = 0
for report in report_File_Dir:
    report_File_Path = report_File_Dir_Path + report + '/'
    reports_Dir = os.listdir(report_File_Path)
    for file in reports_Dir:
        report_file = open(report_File_Dir_Path + report + '/' + file, 'r', encoding='UTF-8')
        try:
            report_Data = json.load(report_file)
        except:
            print(report + ' load exception')

        try:
            extract_File_Name = report_Data['target']['file']['name']
            report_file.close()

            old_File_Name = report_File_Path + file
            new_file_Name = report_File_Path + extract_File_Name + '.json'

            rename(old_File_Name,  new_file_Name)
            print('count : ' + str(count) + '  ' + file + ' file Rename and check Success!!')
        except KeyError:
            print('count : ' + str(count) +'  file name : ' + file + ' KeyError -----> Baseline file or Error file >>>>> !!!! Need to check file type !!!!')
            report_file.close()
        except:
            print('count : ' + str(count) +'  file name : ' + file + ' execept!!')
            report_file.close()

        count += 1

    print('>>>>>>>>>>>' + report + ' file end!!')


