import csv
import os
import shutil

def name_Classification(entropy, entropy_Info_Path, packed_Info_Path, dataset_Info_Path):
    entropy_Info_File = open(entropy_Info_Path, 'r', encoding='utf-8')
    packed_Info_File = open(packed_Info_Path, 'r', encoding='utf-8')
    entropy_Info = csv.reader(entropy_Info_File)
    packed_Info = csv.reader(packed_Info_File)

    dataset_Name = []

    for data in entropy_Info:
        if (float)(data[3]) < entropy:
            dataset_Name.append(data[0])

    for data in packed_Info:
        if (float)(data[2]) >= entropy:
            dataset_Name.append(data[0])

    dataset_Info_File = open(dataset_Info_Path, 'w', encoding='utf-8')

    for name in dataset_Name:
        dataset_Info_File.write(name + '\n')

    entropy_Info_File.close()
    packed_Info_File.close()
    dataset_Info_File.close()

def file_Classification(list_path, copy_file_path, copy_save_path):
    copy_file_list_file = open(list_path, 'r', encoding='utf-8')
    copy_file_list = csv.reader(copy_file_list_file)

    copy_file_name = []
    for name in copy_file_list:
        copy_file_name.append(name[0].replace('.vir', '.json'))

    for file in copy_file_name:
        try:
            shutil.copy(os.path.join(copy_file_path, file), os.path.join(copy_save_path, file))
        except:
            pass

def __main__():
    entropy_Info_path = './data_info/zero_entropy_list.csv'
    packed_Info_path = './data_info/packingData.csv'
    case1_save_path = 'C:/Users/ucloud/Desktop/6dot8_Dataset.csv'
    case2_save_path = 'C:/Users/ucloud/Desktop/7dot0_Dataset.csv'
    case3_save_path = 'C:/Users/ucloud/Desktop/7dot2_Dataset.csv'

    copy_file_path = 'C:/Users/ucloud/Desktop/extracted Data/'
    copy_case1_save_path = 'C:/Users/ucloud/Desktop/6dot8_Dataset/'
    copy_case2_save_path = 'C:/Users/ucloud/Desktop/7dot0_Dataset/'
    copy_case3_save_path = 'C:/Users/ucloud/Desktop/7dot2_Dataset/'

    name_Classification(6.8, entropy_Info_path, packed_Info_path, case1_save_path)
    name_Classification(7.0, entropy_Info_path, packed_Info_path, case2_save_path)
    name_Classification(7.2, entropy_Info_path, packed_Info_path, case3_save_path)

    file_Classification(case1_save_path, copy_file_path, copy_case1_save_path)
    file_Classification(case2_save_path, copy_file_path, copy_case2_save_path)
    file_Classification(case3_save_path, copy_file_path, copy_case3_save_path)

    print('Dataset_Entropy_Classification successful!')

__main__()