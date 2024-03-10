import json
import csv
import time
import os

file_path = "./reports/"
report_dir = os.listdir(file_path)
count = 0
for file in report_dir:
    try:
        report_file = open(file_path + str(file), 'r')
        report_data = json.load(report_file)
        print(file)

        # behavior:processes:calls (Includes category and api)
        try:
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

        except KeyError:
            print(file + ' KeyError!!')
            api_list = []
            category_num = []

        except :
            print(file + " Except!!")
            api_list = []
            category_num = []

        report_file.close()

        f = open('./'+str(file)+'.csv', 'w', newline='', encoding='utf-8')
        wr = csv.writer(f)
        for value in api_list:
            wr.writerow(value)
        f.close()
    except:
        print(file + " Except!!")
        api_list = []
        category_num = []
        report_file.close()

    count += 1
    print('Number of files with successful data extraction: %d/%d' % (count, len(report_dir)))
