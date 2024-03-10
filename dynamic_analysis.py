import os
import csv
import json


class CuckooReportParser:
    def __init__(self, reports_base_dir, log_base_dir, saved_base_dir):
        """ata 저장 base dir
        Extract features(opcode, API calls, DLLs, Strings) at PE file

        :param reports_base_dir : cuckoo reports 저장된 directory
        :param log_base_dir : log 파일 저장하는 directory
        :param saved_base_dir : output 저장 directory
        """
        # Base directory
        self.REPORTS_BASE_DIR = reports_base_dir
        self.LOG_BASE_DIR = log_base_dir
        self.SAVED_BASE_DIR = saved_base_dir

        # Extracted feature 저장 path
        self.PARSING_OUTPUT_DIR = os.path.join(saved_base_dir, 'parsing_output')

        # File path
        self.COMPLETE_REPORTS_LOG = os.path.join(log_base_dir, 'parsing_complete_reports.txt')
        self.NO_BEHAVIOR_REPORTS_LOG = os.path.join(log_base_dir, 'no_behavior_reports.csv')

        # directory init 생성
        if not os.path.exists(self.LOG_BASE_DIR):
            os.makedirs(self.LOG_BASE_DIR)
        if not os.path.exists(self.PARSING_OUTPUT_DIR):
            os.makedirs(self.PARSING_OUTPUT_DIR)

        # file init 생성
        if not os.path.isfile(self.COMPLETE_REPORTS_LOG):
            f = open(self.COMPLETE_REPORTS_LOG, 'w')
            f.close()

    def parse_reports(self):
        self.extract_api_calls()
        self.extract_behaviors()

    def extract_api_calls(self):
        """ extraction.py 개조 """
        reports_list = os.listdir(self.REPORTS_BASE_DIR)
        count = 0
        for report in reports_list:
            with open(os.path.join(self.REPORTS_BASE_DIR, str(report)), 'r') as report_file:
                try:
                    report_data = json.load(report_file)

                    # behavior:processes:calls (Includes category and api)
                    calls_num = len(report_data['behavior']['processes'][0:])
                    # print('calls num = ' + str(len(report_data['behavior']['processes'][0:])))

                    # calls:category and api count
                    category_num = []
                    for call in range(0, calls_num):
                        category_num.append(len(report_data['behavior']['processes'][call]['calls']))
                    # print('list count = ' + str(category_num))

                    api_list = []
                    # iteration (Extract category and api)
                    for iter in range(0, len(category_num)):
                        for extract in range(0, category_num[iter]):
                            category = report_data['behavior']['processes'][iter]['calls'][extract]['category']
                            api = report_data['behavior']['processes'][iter]['calls'][extract]['api']
                            api_list.append([category, api])
                            # print(api_list)

                    with open(os.path.join(self.PARSING_OUTPUT_DIR, '%s.csv' % report), 'w', newline='', encoding='utf-8') as f:
                        wr = csv.writer(f)
                        for value in api_list:
                            wr.writerow(value)

                    count += 1
                    print('report name = %s  ||  extraction: %d/%d' % (report, count, len(reports_list)))

                except Exception as e:
                    print(str(e))

    def extract_behaviors(self):
        """ behaviorCheck.py 개조 """
        reports_list = os.listdir(self.REPORTS_BASE_DIR)
        none_extracted_reports_List = []
        count = 0
        for report in reports_list:
            with open(os.path.join(self.REPORTS_BASE_DIR, str(report)), 'r') as report_file:
                try:
                    report_data = json.load(report_file)
                    
                    # behavior 항목이 없는 경우
                    if 'behavior' not in report_data:
                        print('count = %d || file name : %s >>>>>>>> no behavior' % (count, report))
                        none_extracted_reports_List.append(report)
                    else:
                        # behavior - processes 항목이 없는 경우
                        if 'processes' not in report_data['behavior']:
                            none_extracted_reports_List.append(report)
                            print('count = %d || file name : %s  >>>>>>>> no behavior - processes' % (count, report))
                        else:
                            print('count = %d || success to extract processes' % count)

                    with open(self.NO_BEHAVIOR_REPORTS_LOG, 'w', newline='', encoding='utf-8') as f:
                        for value in none_extracted_reports_List:
                            f.write(value + '\n')

                    count += 1
                except Exception as e:
                    print(str(e))

    def dir_rename(self):
        """ dir_rename.py 개조 """
        """ 요건 뭘까... """
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

                    rename(old_File_Name, new_file_Name)
                    print('count : ' + str(count) + '  ' + file + ' file Rename and check Success!!')
                except KeyError:
                    print('count : ' + str(
                        count) + '  file name : ' + file + ' KeyError -----> Baseline file or Error file >>>>> !!!! Need to check file type !!!!')
                    report_file.close()
                except:
                    print('count : ' + str(count) + '  file name : ' + file + ' execept!!')
                    report_file.close()

                count += 1

            print('>>>>>>>>>>>' + report + ' file end!!')


if __name__ == '__main__':
    cuckoo_parser = CuckooReportParser(reports_base_dir='', log_base_dir='', saved_base_dir='')
    cuckoo_parser.parse_reports()