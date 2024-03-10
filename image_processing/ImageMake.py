from builtins import len

import numpy as np
import time
import os
import csv
from sklearn.feature_extraction.text import TfidfVectorizer
from PIL import Image
import matplotlib.pylab as plt

# Read entire file
def readOfData():
    path = "C:/Users/Desktop/test/" # change
    # file_list = os.listdir(path)

    file_name = []
    data_list_file = open('C:/Users/Desktop/dataset2.csv', 'r', encoding='utf-8')    # change
    data_list = csv.reader(data_list_file)

    for name in data_list:
        file_name.append(name[0].replace('.vir','.json.csv')) # change
    # print(file_name)
    print(len(file_name))

    doc_Category = []
    doc_API = []
    all_Data = []
    total_Data = []
    tmp_Data = []
    category = []
    api = []
    file_Name = []
    check_Count = 0
    for file in file_name:
        file_Name.append(file)
        file_Read = open(path + file, 'r')
        read_Data = csv.reader(file_Read)

        for line in read_Data:
            category.append(line[0])
            api.append(line[1])
            all_Data.append(line)
            tmp_Data.append(line)
        total_Data.append(tmp_Data)

        doc_Category.append(category)
        doc_API.append(api)
        category = []
        api = []
        tmp_Data = []
        check_Count += 1
        print('file count : ' + str(check_Count))

        file_Read.close()

    print(">>>>>>>>>>>>>>>> File read success!!")
    # print(all_Data)
    # print(total_Data)
    print(doc_API)
    '''
    all_Data 2차원 리스트 -> 전체 파일의 [cate, api]가 순서대로 저장
    total_Data 3차원 리스트 -> 파일별로 [cate, api] 저장
    doc_API 2차원 리스트 -> 파일별로[api] 저장 

    '''

    f = open('C:/Users/Desktop/temp.csv', 'w', newline='', encoding='utf-8')  # change
    wr = csv.writer(f)
    for line in doc_API:
        wr.writerow(line)
    f.close()

    tmp = []
    data_list_file = open('C:/Users/Desktop/temp.csv', 'r', encoding='utf-8')  # change
    data_list = csv.reader(data_list_file)
    for line in data_list:
        tmp.append(line)

    print(tmp)
    print(type(tmp))
    print(type(tmp[0]))

    return doc_Category, doc_API, all_Data, total_Data, file_Name  # Total category, Total API, Total Data

def categorization(doc_Category, doc_API, all_Data):
    all_Category = []
    all_API = []

    for c_List in doc_Category:
        for word in c_List:
            all_Category.append(word)

    for a_List in doc_API:
        for word in a_List:
            all_API.append(word)

    # Category & API deduplication
    set_Category = set(all_Category)
    category = list(set_Category)
    category.sort()
    print('>>>>>>> category')
    print(category)
    print('category count : ' + str(len(category)))

    set_API = set(all_API)
    api = list(set_API)
    api.sort()
    print('>>>>>>> api')
    print(api)
    print('api count : ' + str(len(api)))

    # API count that is not duplicated by category
    count_APIByCategory = [0] * len(category)

    tmp = []
    APIByCategory = []

    for cate in category:
        for data in all_Data:
            if cate == data[0] and data[1] not in tmp:
                tmp.append(data[1])
                count_APIByCategory[category.index(data[0])] += 1
        APIByCategory.append(tmp)
        tmp = []

    print('>>>>>>> count_APICategory')
    print(count_APIByCategory)
    print('>>>>>>> APIByCategory')
    print(APIByCategory)
    print(">>>>>>>>>>>>>>>> Categorization success!!")
    return category, count_APIByCategory, APIByCategory

def digitization(category, count_API, APIByCategory):
    category_Digit = []
    api_Digit = []
    tmp_API_Digit = []

    category_Size = len(category)
    category_Label = int(256 / category_Size)

    for i in range(1, category_Size + 1):
        if category_Label * i > 255 and i == category_Size:
            category_Digit.append(255)
        else:
            category_Digit.append(category_Label * i)
    print('>>>>>>> category digit')
    print(category_Digit)

    f = open('C:/Users/Desktop/temp.csv', 'w', newline='', encoding='utf-8')  # change
    wr = csv.writer(f)
    for line in api_Digit:
        wr.writerow(line)
    f.close()

    tmp = []
    # data_list_file = open('C:/Users/Desktop/temp.csv', 'r', encoding='utf-8')  # change
    # data_list = csv.reader(data_list_file)
    # print('sb')
    # for a in data_list:
    #     tmp = a

    data_list_file = open('C:/Users/Desktop/temp.csv', 'r', encoding='utf-8')  # change
    data_list = csv.reader(data_list_file)
    for line in data_list:
        tmp.append(line)

    print("checkpoint")
    print(tmp)
    list_a = list(map(int, tmp))
    print(list_a)


    api_Size = count_API
    api_Label = []

    for i in api_Size:
        if int(256 / i) > 255:
            api_Label.append(255)
        else:
            api_Label.append(int(256 / i))

    count = 0
    for label in api_Label:
        for i in range(1, api_Size[count]+1):
            if label * i > 255 and i == api_Size[count]:
                tmp_API_Digit.append(255)
            else:
                tmp_API_Digit.append(label * i)
        api_Digit.append(tmp_API_Digit)
        tmp_API_Digit = []
        count += 1
    print('>>>>>>> api digit')
    print(api_Digit)
    print(">>>>>>>>>>>>>>>> Digitization success!!")

    f = open('C:/Users/Desktop/temp.csv', 'w', newline='', encoding='utf-8')  # change
    wr = csv.writer(f)
    for line in api_Digit:
        wr.writerow(line)
    f.close()

    tmp = []
    # data_list_file = open('C:/Users/Desktop/temp.csv', 'r', encoding='utf-8')  # change
    # data_list = csv.reader(data_list_file)
    # print('sb')
    # for a in data_list:
    #     tmp = a

    data_list_file = open('C:/Users/Desktop/temp.csv', 'r', encoding='utf-8')  # change
    data_list = csv.reader(data_list_file)
    print('gsk')
    for line in data_list:
        print(line)
        tmp.append(list(map(int,line)))

    print(tmp)

    tmp3 = []
    for a in tmp:
        tmp3.append(list(map(int,a)))

    # list_a = list(map(int, tmp))
    print(tmp3)

    # f = open('./MODEL_API_DIGIT.csv', 'w', newline='', encoding='utf-8')  # change
    # wr = csv.writer(f)
    # for line in api_Digit:
    #     # for value in line:
    #     wr.writerow(line)
    # f.close()
    return category_Digit, api_Digit

def TFIDF(doc_API):
    doc = []
    term = ''

    a = []
    for file in doc_API:
        for line in file:
            term += line + ' '
        doc.append(term)
        term = ''

    tfidfv = TfidfVectorizer().fit(doc)
    dic = tfidfv.vocabulary_
    TFIDF_Value_List = list(tfidfv.transform(doc).toarray())
    # TFIDF_Value_List = list(tfidfv.transform(a).toarray())
    print(TFIDF_Value_List)
    doc_Value = []
    tmp_Value = []
    count = 0
    for api_List in doc_API:
        for api in api_List:
            api = api.lower()
            try:
                tmp_Value.append(dic['api'])
                print(dic[api])
            except:
               tmp_Value.append(0)
        doc_Value.append(tmp_Value)
        tmp_Value = []
        count += 1
        print('Number of completed api list = %d/%d' % (count, len(doc_API)))
    print('>>>>>>> doc_Value pass')
    print(doc_Value)

    api_Label = []
    tmp_Label = []

    # tf-idf 값을 각 파일별 api에 매핑시킴.
    count = 0
    for api_Value_Low in doc_Value:
        for value in api_Value_Low:
            tmp_Label.append(TFIDF_Value_List[count][value])
        api_Label.append(tmp_Label)
        tmp_Label = []
        count += 1
        print('Number of completed api values = %d/%d' % (count, len(doc_Value)))
    print(api_Label)
    print('>>>>>>> api label pass')

    TFIDF_Range = []
    cut_Size = 16
    for i in range(1, cut_Size + 1):
        TFIDF_Range.append(i / cut_Size)
    print(TFIDF_Range)
    print(len(TFIDF_Range))

    pre_TFIDF = []
    tmp = []
    for i in range(0, len(api_Label)):
        for j in range(0, len(api_Label[i])):
            for ran in range(0, len(TFIDF_Range)):
                if ran == 0:
                    if 0 <= api_Label[i][j] < TFIDF_Range[ran]:
                        tmp.append((ran + 1) * cut_Size)
                elif 0 < ran < len(TFIDF_Range)-1:
                    if TFIDF_Range[ran - 1] <= api_Label[i][j] < TFIDF_Range[ran]:
                        tmp.append((ran + 1) * cut_Size)
                elif ran == len(TFIDF_Range)-1:
                    if TFIDF_Range[ran - 1] <= api_Label[i][j] <= TFIDF_Range[ran]:
                        tmp.append((ran + 1) * cut_Size - 1)
        print('count of files with TF-IDF applied = %d/%d' % ((i+1), len(api_Label)))
        pre_TFIDF.append(tmp)
        tmp = []
    print('>>>>>>> TF-IDF norm value')
    print(pre_TFIDF) # 최종 tf-idf 값
    print(">>>>>>>>>>>>>>>> TFIDF success!!")

    return pre_TFIDF

def makeOfVocab(total_Data, pre_Category, APIByCategory, category_Digit, api_Digit, pre_TFIDF, file_Name):
    file_Vocab = []
    total_Vocab = []
    count = 0
    t_Row = 0
    t_Colunms = 0
    print('pre_cate')
    print(pre_Category)
    print(APIByCategory)
    print(category_Digit)
    print(api_Digit)

    data_count = 0
    for data in total_Data: # data -> 한개 파일
        for word in data: # word -> [c, a]
            for category in range(0, len(pre_Category)):
                if word[0] == pre_Category[category]:
                    c = category_Digit[category]
                    for api in APIByCategory[category]:
                        if word[1] == api:
                            a = api_Digit[category][count]
                        count += 1
                    count = 0
            t = pre_TFIDF[t_Row][t_Colunms]
            file_Vocab.append([c, a, t])
            t_Colunms += 1
        total_Vocab.append(file_Vocab)
        t_Row += 1
        t_Colunms = 0
        file_Vocab = []
        data_count += 1
        print('count of made vocab = %d/%d' % (data_count, len(total_Data)))

    print(">>>>>>>>>>>>>>>> Vocab creation success!!")

    # check
    print('length of total_Vocab  : ' + str(len(total_Vocab)))
    print('length of file : ' + str(len(file_Name)))

    # for vocab_Write_Count in range(0, len(total_Vocab)):
    vocab_Write_Count = 0
    for name in file_Name:  # change
        f = open('C:/Users/Desktop/dataset_vocab/'+name+'.csv', 'w', newline='', encoding='utf-8')  # change
        wr = csv.writer(f)
        for value in total_Vocab[vocab_Write_Count]:
            wr.writerow(value)
        f.close()
        vocab_Write_Count += 1
    print('count of written vocab : ' + str(vocab_Write_Count))
    print(">>>>>>>>>>>>>>>> csv file creation success!!")

# 그대로 사용
def make_RGB_Image(vocab_Path):

    # Read file size (To find the width size)
    file_Infor_Count = 0
    # file_Infor_Size = []
    image_Width_Size = [32, 64, 128, 256, 384, 512, 768, 1024]
    file_Width_Range = [0, 10, 30, 60, 100, 200, 500, 1000]
    # file_Infor = open('file_infor.csv', 'r') # csv file change
    # file_Infor_Read = csv.reader(file_Infor)

    # for size in file_Infor_Read:
    #     file_Infor_Size.append(size[1])

    # get RGB pixel value
    file_List = os.listdir(vocab_Path)
    # print(file_List)

    make_count = 0
    height_1_cnt = 0
    for vocab in file_List:
        file_Read = open(vocab_Path + str(vocab), 'r')
        read_Data = csv.reader(file_Read)

        data = []

        for line in read_Data:
            data.append(line)
        # print(len(data))

        # change
        file_Size_Path = 'C:/Users/Desktop/dataset_vocab/'
        file_List = os.listdir(file_Size_Path)

        file_Size = []
        for file in file_List:
            size = os.path.getsize(file_Size_Path + file)
            file_Size.append(size)
        # print('file size len : ' + str(len(file_Size)))

        # file size change
        # BYTE -> KILOBYTE
        # image_Width_Calc = (int)((int)(file_Infor_Size[file_Infor_Count]) / 1024)
        # image_Width_Calc = (int)(file_Infor_Size[file_Infor_Count])
        image_Width_Calc = (int)((int)(file_Size[file_Infor_Count]) / 1024)
        file_Infor_Count += 1

        for ran in range(0, len(file_Width_Range)):
            if ran == 0:
                if file_Width_Range[ran] <= image_Width_Calc < file_Width_Range[ran + 1]:
                    width = image_Width_Size[ran]
            elif 0 < ran < len(file_Width_Range)-1:
                if file_Width_Range[ran] <= image_Width_Calc < file_Width_Range[ran + 1]:
                    width = image_Width_Size[ran]
            elif ran == len(file_Width_Range)-1:
                if file_Width_Range[ran] <= image_Width_Calc:
                    width = image_Width_Size[ran]

        height = (int)((len(data) / width) + 1)
        array = np.array(data, dtype=np.uint8)
        image = np.zeros((height, width, 3), dtype=np.uint8)


        count = 0

        if height > 1:
            for h in range(0, height):
                for w in range(0, width):
                    if(count >= len(data)):
                        image[h, w] = [0, 0, 0]
                    else:
                        image[h, w] = array[count]
                    count += 1
            # change
            img = Image.fromarray(image, 'RGB')
            img.save('C:/Users/Desktop/img/'+str(vocab).split('.json.csv.csv')[0]+'.jpg')
        else:
            height_1_cnt += 1

        make_count += 1
        print('count of made image = %d/%d' % (make_count,len(file_List)))
    print('Number of data with height 1 = %d' % (height_1_cnt))
    print(">>>>>>>>>>>>>>>> Image creation success!!")

def main():
    category, api, all_Data, total_Data, file_Name = readOfData()
    pre_Category, count_API, APIByCategory = categorization(category, api, all_Data)
    del category
    del all_Data
    category_Digit, api_Digit = digitization(pre_Category, count_API, APIByCategory)
    del count_API
    pre_TFIDF = TFIDF(api)
    makeOfVocab(total_Data, pre_Category, APIByCategory, category_Digit, api_Digit, pre_TFIDF, file_Name)
    del total_Data
    del file_Name
    del pre_Category
    del APIByCategory
    del category_Digit
    del api_Digit
    make_RGB_Image('C:/Users/Desktop/dataset_vocab/')  # change

main()
