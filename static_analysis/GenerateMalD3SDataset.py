import os
import re
import io
import csv
import sys
import copy
import json
import math
import time
import shutil
import pefile
import pydasm
import logging
import datetime
import traceback
import numpy as np
from PIL import Image
from pyparsing import Word, hexnums, WordEnd, Optional, alphas, alphanums, SkipTo

import gensim
from gensim import utils
from gensim.models import word2vec
from gensim.models.fasttext import FastText, FastTextKeyedVectors


ASN_DATASET_PATH = 'C://Users/Ucloud/Downloads/malware-classification/asm_files'    # BIG2015 dataset
PE_DATASET_PATH = './KISAset/benign'                                                # KISA(benign) dataset
# ASN_DATASET_PATH = 'C://Users/Ucloud/Downloads/malware-classification/test'    # BIG2015 dataset
# PE_DATASET_PATH = './test/kisa'                                                # KISA(benign) dataset

DATASET_SRC_PATH = './TotalSet/'
ASN_LABEL_FILE = './TotalSet/BIG2015_Labels.csv'
TOTAL_LABEL_FILE = './TotalSet/TOTAL_LABELS.csv'
TRAIN_SET_FILE = './TotalSet/train.csv'
VALID_SET_FILE = './TotalSet/valid.csv'
TEST_SET_FILE = './TotalSet/test.csv'
BENIGN_FILE_PATH = './KISAset/benign'
# PE_LABEL_FILE = './Total_Dataset/trainSet.csv'

FASTTEXT_BASE_DIR = os.path.join(DATASET_SRC_PATH, 'FastText')
FASTTEXT_MODEL_PATH = os.path.join(FASTTEXT_BASE_DIR, 'models')

IMG_SRC_PATH = os.path.join(DATASET_SRC_PATH, 'IMAGE')

# Feature 1
BYTE_IMG_PATH = os.path.join(IMG_SRC_PATH, 'Byte_IMG')
# Feature 2
OPCODE64_IMG_PATH = os.path.join(IMG_SRC_PATH, 'opcode_IMG/64')
OPCODE128_IMG_PATH = os.path.join(IMG_SRC_PATH, 'opcode_IMG/128')
OPCODE256_IMG_PATH = os.path.join(IMG_SRC_PATH, 'opcode_IMG/256')
OPCODE512_IMG_PATH = os.path.join(IMG_SRC_PATH, 'opcode_IMG/512')
# Feature 3
API64_IMG_PATH = os.path.join(IMG_SRC_PATH, 'API_IMG/64')
API128_IMG_PATH = os.path.join(IMG_SRC_PATH, 'API_IMG/128')
API256_IMG_PATH = os.path.join(IMG_SRC_PATH, 'API_IMG/256')
API512_IMG_PATH = os.path.join(IMG_SRC_PATH, 'API_IMG/512')
# Feature 4
DLL_API_SET_PATH = os.path.join('./TotalSet/DLLAPI/')
DLL_API_IMG_PATH = os.path.join(IMG_SRC_PATH, 'DllApi_IMG')
# Feature 5
STRING_IMG_PATH = os.path.join(IMG_SRC_PATH, 'string_IMG')


def GenerateDatasetLabel():
    file_label_dict = {}
    with open(TOTAL_LABEL_FILE, 'wb') as f:
        wr = csv.writer(f)

        # read and write about BIG2015 dataset
        with open(ASN_LABEL_FILE, 'r') as asm_label:
            rdr = csv.reader(asm_label)
            for line in rdr:
                if line[0] == "Id":
                    continue
                file_label_dict['%s.jpg' % line[0]] = line[1]
                wr.writerow(['%s.jpg' % line[0], line[1]])

        # read benign file list and write name and label of benign
        benign_list = os.listdir(BENIGN_FILE_PATH)
        benign_list = [word.replace('.vir', '.jpg') for word in benign_list]
        for benign_hash in benign_list:
            file_label_dict[benign_hash] = 0
            wr.writerow([benign_hash, 0])

    # category_cnt_list = [0, 0, 0, ..., 0]
    category_cnt_list = []
    for i in range(10):
        category_cnt_list.append(0)

    # count label and divide num of train, valid, test
    for key in file_label_dict:
        label_value = file_label_dict[key]
        category_cnt_list[int(label_value)] += 1

    train_label_cnt_list = []
    valid_label_cnt_list = []
    test_label_cnt_list = []
    for category_cnt in category_cnt_list:
        train_num = int(category_cnt * 0.8)
        train_label_cnt_list.append(train_num)

        test_num = int(category_cnt - train_num) // 2
        test_label_cnt_list.append(test_num)

        valid_num = int(category_cnt) - train_num - test_num
        valid_label_cnt_list.append(valid_num)

    # generate train.csv, valid.csv, test.csv
    for key in file_label_dict:
        label_value = int(file_label_dict[key])

        if train_label_cnt_list[label_value] != 0:
            with open(TRAIN_SET_FILE, 'ab') as train_csv:
                wr = csv.writer(train_csv)
                wr.writerow([key, label_value])
            train_label_cnt_list[label_value] -= 1

        elif valid_label_cnt_list[label_value] != 0:
            with open(VALID_SET_FILE, 'ab') as valid_csv:
                wr = csv.writer(valid_csv)
                wr.writerow([key, label_value])
            valid_label_cnt_list[label_value] -= 1

        elif test_label_cnt_list[label_value] != 0:
            with open(TEST_SET_FILE, 'ab') as test_csv:
                wr = csv.writer(test_csv)
                wr.writerow([key, label_value])
            test_label_cnt_list[label_value] -= 1


def GenerateNoneImg():
    def ProcessByteImg(label_list):
        # get Minimum image size
        img_name = os.listdir(BYTE_IMG_PATH)
        file_size_dict = {}
        min_size = 100000000
        min_size_img = ''
        for img in img_name:
            file_size = os.path.getsize(os.path.join(BYTE_IMG_PATH, img))
            if file_size < min_size:
                min_size = file_size
                min_size_img = img

        min_img = Image.open(os.path.join(BYTE_IMG_PATH, min_size_img))
        min_width, min_height = min_img.size

        # find None Image and Generate Minimum size Image
        matrix_ = np.zeros((min_height, min_width), dtype=np.uint8)
        for file_name in label_list:
            if file_name not in img_name:
                img = Image.fromarray(matrix_, 'L')
                img.save(os.path.join(BYTE_IMG_PATH, file_name))
        print('finish ProcessByteImg...')

    def ProcessDLLAPIImg(file_list):
        # get Minimum image size
        img_name = os.listdir(DLL_API_IMG_PATH)
        file_size_dict = {}
        min_size = 100000000
        min_size_img = ''
        for img in img_name:
            file_size = os.path.getsize(os.path.join(DLL_API_IMG_PATH, img))
            if file_size < min_size:
                min_size = file_size
                min_size_img = img

        min_img = Image.open(os.path.join(DLL_API_IMG_PATH, min_size_img))
        min_width, min_height = min_img.size

        # find None Image and Generate Minimum size Image
        matrix_ = np.zeros((min_height, min_width), dtype=np.uint8)
        for file_name in label_list:
            if file_name not in img_name:
                img = Image.fromarray(matrix_, 'L')
                img.save(os.path.join(DLL_API_IMG_PATH, file_name))
        print('finish ProcessDLLAPIImg...')

    def ProcessStringImg(file_list):
        # get Minimum image size
        img_name = os.listdir(STRING_IMG_PATH)
        file_size_dict = {}
        min_size = 100000000
        min_size_img = ''
        for img in img_name:
            file_size = os.path.getsize(os.path.join(STRING_IMG_PATH, img))
            if file_size < min_size:
                min_size = file_size
                min_size_img = img

        min_img = Image.open(os.path.join(STRING_IMG_PATH, min_size_img))
        min_width, min_height = min_img.size

        # find None Image and Generate Minimum size Image
        matrix_ = np.zeros((min_height, min_width), dtype=np.uint8)
        for file_name in label_list:
            if file_name not in img_name:
                img = Image.fromarray(matrix_, 'L')
                img.save(os.path.join(STRING_IMG_PATH, file_name))
        print('finish ProcessStringImg...')

    def ProcessOpcodeImg(file_list):
        FastText_List = [OPCODE64_IMG_PATH, OPCODE128_IMG_PATH, OPCODE256_IMG_PATH, OPCODE512_IMG_PATH]
        for IMG_PATH in FastText_List:
            # get Minimum image size
            img_name = os.listdir(IMG_PATH)
            file_size_dict = {}
            min_size = 100000000
            min_size_img = ''
            for img in img_name:
                file_size = os.path.getsize(os.path.join(IMG_PATH, img))
                if file_size < min_size:
                    min_size = file_size
                    min_size_img = img

            min_img = Image.open(os.path.join(IMG_PATH, min_size_img))
            min_width, min_height = min_img.size

            # find None Image and Generate Minimum size Image
            matrix_ = np.zeros((min_height, min_width), dtype=np.uint8)
            for file_name in label_list:
                if file_name not in img_name:
                    img = Image.fromarray(matrix_, 'L')
                    img.save(os.path.join(IMG_PATH, file_name))
        print('finish ProcessOpcodeImg...')

    def ProcessAPIImg(file_list):
        FastText_List = [API64_IMG_PATH, API128_IMG_PATH, API256_IMG_PATH, API512_IMG_PATH]
        for IMG_PATH in FastText_List:
            # get Minimum image size
            img_name = os.listdir(IMG_PATH)
            file_size_dict = {}
            min_size = 100000000
            min_size_img = ''
            for img in img_name:
                file_size = os.path.getsize(os.path.join(IMG_PATH, img))
                if file_size < min_size:
                    min_size = file_size
                    min_size_img = img

            min_img = Image.open(os.path.join(IMG_PATH, min_size_img))
            min_width, min_height = min_img.size

            # find None Image and Generate Minimum size Image
            matrix_ = np.zeros((min_height, min_width), dtype=np.uint8)
            for file_name in label_list:
                if file_name not in img_name:
                    img = Image.fromarray(matrix_, 'L')
                    img.save(os.path.join(IMG_PATH, file_name))
        print('finish ProcessAPIImg...')

    label_list = []
    with open(TOTAL_LABEL_FILE, 'r') as total_label:
        rdr = csv.reader(total_label)
        for line in rdr:
            label_list.append(line[0])

    # print("Generate Byte None Image...")
    # ProcessByteImg(label_list)

    # print("Generate DLL-API None Image...")
    # ProcessDLLAPIImg(label_list)

    # print("Generate String None Image...")
    # ProcessStringImg(label_list)

    print("Generate opcode None Image...")
    ProcessOpcodeImg(label_list)

    print("Generate API None Image...")
    ProcessAPIImg(label_list)



def PrintFastTextValue():
    name_list = ['API', 'OPCODE']
    embedding_list = [64, 128, 256, 512]
    for name in name_list:
        for embedding_size in embedding_list:
            print('print and save about %s - %s size...' % (name, embedding_size))
            FastText_file = os.path.join(FASTTEXT_MODEL_PATH, '%s_%ssize' % (name, embedding_size))
            FastText_model = FastText.load(FastText_file)

            words = []
            for i in range(len(FastText_model.wv.vocab)):
                words.append(FastText_model.wv.index2word[i])

            embedding_matrix = np.zeros((len(words), embedding_size))
            embedding_vector_dict = {}
            with open(os.path.join(FASTTEXT_BASE_DIR, '%s_%ssize_original_FastText_Value.csv' % (name, embedding_size)), 'wb') as f:
                wr = csv.writer(f)
                for i in range(len(words)):
                    if words[i] in FastText_model.wv.vocab:
                        # write original vectors
                        embedding_vector_list = FastText_model.wv[words[i]].tolist()
                        print_vector_list = copy.deepcopy(embedding_vector_list)
                        print_vector_list.insert(0, str(words[i]))
                        wr.writerow(print_vector_list)

                        # Save vector for Normalization
                        embedding_vector_dict[words[i]] = embedding_vector_list
                        embedding_vector = FastText_model.wv[words[i]]
                        embedding_matrix[i] = embedding_vector

            max_value = embedding_matrix.max()
            min_value = embedding_matrix.min()

            # write Normalized vector
            with open(os.path.join(FASTTEXT_BASE_DIR, '%s_%ssize_Normalized_FastText_Value.csv' % (name, embedding_size)), 'wb') as f:
                wr = csv.writer(f)
                for key in words:
                    print_vector_list = []
                    print_vector_list.append(str(key))
                    value_list = embedding_vector_dict[key]
                    for cnt in range(len(value_list)):
                        normalized_value = int(255 * ((value_list[cnt] - min_value) / (max_value - min_value)))
                        print_vector_list.append(normalized_value)
                    wr.writerow(print_vector_list)


def Dissect_FastText():
    name_list = ['API', 'OPCODE']
    embedding_list = [64, 128, 256, 512]
    for name in name_list:
        for embedding_size in embedding_list:
            print('print and Dissect about %s - %s size...' % (name, embedding_size))
            FastText_file = os.path.join(FASTTEXT_MODEL_PATH, '%s_%ssize' % (name, embedding_size))
            FastText_model = FastText.load(FastText_file)

            # https://stackoverflow.com/questions/51594165/how-i-can-extract-matrixes-wi-and-wo-from-gensim-word2vec
            # embeddings for vocabulary words (WI) (same with FastText_model.wv.syn0)
            # shape : [vocab, embedding size]
            print('\n\nFastText_model.wv.vectors')
            # print(FastText_model.wv.vectors)
            print(FastText_model.wv.vectors.shape)



            # Weights of the hidden layer in the model's trainable neural network (hidden-to-output weights)
            # shape : [vocab, embedding size]
            print('\n\nFastText_model.trainables.syn1')
            # print(FastText_model.trainables.syn1)
            print(FastText_model.trainables.syn1.shape)


            # hidden-to-output weights for negative-sampling mode (WO)
            # shape : [vocab, embedding size]
            print('\n\nFastText_model.trainables.syn1neg')
            # print(FastText_model.trainables.syn1neg)
            print(FastText_model.trainables.syn1neg.shape)

            # (same with FastText_model.trainables.syn1neg)
            # shape : [vocab, embedding size]
            print('\n\nFastText_model.syn1neg')
            # print(FastText_model.syn1neg)
            print(FastText_model.syn1neg.shape)



            # full-word-token vectors as trained by the FastText algorithm, for full-words of interest
            # shape : [vocab, embedding size]
            print('\n\nFastText_model.wv.vectors_vocab')
            # print(FastText_model.wv.vectors_vocab)
            print(FastText_model.wv.vectors_vocab.shape)



            # buckets storing the vectors that are learned from word-fragments (character-n-grams)
            # same with FastText_model.wv.syn0_ngrams
            # shape : [buckets size, embedding size]
            print('\n\nFastText_model.wv.vectors_ngrams')
            # print(FastText_model.wv.vectors_ngrams)
            print(FastText_model.wv.vectors_ngrams.shape)

            print('\n\nFastText_model.wv.0')
            print(FastText_model.wv.buckets_word)

            FastText_npy1 = os.path.join(FASTTEXT_MODEL_PATH, '%s_%ssize.trainables.vectors_ngrams_lockf.npy' % (name, embedding_size))
            FastText_npy2 = os.path.join(FASTTEXT_MODEL_PATH, '%s_%ssize.wv.vectors_ngrams.npy' % (name, embedding_size))

            # shape : [buckets size, embedding size]
            no1_npy = np.load(FastText_npy1)
            print('\n\nno1_npy.shape')
            print(no1_npy.shape)
            # print(no1_npy[0])

            # shape : [buckets size, embedding size]
            no2_npy = np.load(FastText_npy2)
            print('\nno2_npy.shape')
            print(no2_npy.shape)
            # print(no2_npy[0])


def Generate_APIFrequency_DLLAPIMatrix():
    # with open('./API_LIST.csv', 'r') as f_api:
    #     rdr = csv.reader(f_api)
    #     API_LIST = []
    #     for line in rdr:
    #         API_LIST.append(line[0])
    # with open('./DLL_LIST.csv', 'r') as f_dll:
    #     rdr = csv.reader(f_dll)
    #     DLL_LIST = []
    #     for line in rdr:
    #         DLL_LIST.append(line[0])
    # print('len(API_LIST)')
    # print(len(API_LIST))
    # print('len(DLL_LIST)')
    # print(len(DLL_LIST))
    # # dictionary initialization
    # Frequency_dict = {}
    # for i in range(len(API_LIST)):
    #     Frequency_dict[API_LIST[i]] = 0
    #
    # # extract API and calculate frequency at ASSEMBLY (BIG 2015)
    # hex_integer = Word(hexnums) + WordEnd()
    # API_line = ".text:" + hex_integer + Optional((hex_integer * (1,))) + Word(alphas) + Optional(
    #     Word("ds:" + alphanums)("api"))
    # cnt = 0
    # asm_file_list = os.listdir(ASN_DATASET_PATH)
    # for asm in asm_file_list:
    #     cnt += 1
    #     print('count %d  ||  BIG open %s...' % (cnt, asm))
    #     with io.open(os.path.join(ASN_DATASET_PATH, asm), 'r', encoding='ISO-8859-1') as f:
    #         source = f.read()
    #         lines = source.split('\n')
    #         for source_line in lines:
    #             try:
    #                 result = API_line.parseString(source_line)
    #                 if "api" in result:
    #                     APIname = str(result.api).lower()
    #                     if APIname.find("ds:") != -1:
    #                         APIname = APIname.replace("ds:", "")
    #                     if APIname.find(" ") != -1:
    #                         APIname = APIname.replace(" ", "")
    #                     if APIname in API_LIST:
    #                         Frequency_dict[APIname] += 1
    #             except Exception as e:
    #                 pass
    #
    # print('=' * 100)
    # print('\n')
    #
    # # extract API and calculate frequency at PE files (KISA)
    # pe_file_list = os.listdir(PE_DATASET_PATH)
    # file_cnt = 0
    # for exe_file in pe_file_list:
    #     file_cnt += 1
    #     print("%d  ||  KISA extract API calls at %s ..." % (file_cnt, exe_file))
    #     # Address of Dataset to analysis
    #     current_file = os.path.join(PE_DATASET_PATH, exe_file)
    #     # PE file and file(bytes) open
    #     pe = pefile.PE(current_file)
    #     open_exe = open(current_file, 'rb')
    #     data = open_exe.read()
    #     for sec in pe.sections:
    #         if '.text' in sec.Name:
    #             raw_size = sec.SizeOfRawData
    #
    #     EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    #     EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase
    #
    #     # Start disassembly at the EP
    #     offset = EntryPoint
    #     Endpoint = offset + raw_size
    #
    #     API_dict1, API_dict2 = {}, {}
    #     for item in pe.DIRECTORY_ENTRY_IMPORT:
    #         DLL_data = str(item.dll).lower()
    #         if DLL_data.find('.dll') == -1:
    #             DLL_data += '.dll'
    #         if DLL_data in DLL_LIST:
    #             for import_fn in item.imports:
    #                 try:
    #                     API_name = str(import_fn.name).lower()
    #                     if API_name in API_LIST:
    #                         API_dict1['[%s]' % hex(import_fn.address)] = API_name
    #                         API_dict2[hex(import_fn.address)] = API_name
    #                     else:
    #                         pass
    #                 except:
    #                     pass
    #
    #     # Loop until the end of the .text section => OPCODE list extract
    #     while offset < Endpoint:
    #         # Get the first instruction
    #         i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    #         if not i:
    #             break
    #         try:
    #             op_string1 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
    #             op_string2 = pydasm.get_operand_string(i, 1, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
    #             op_string3 = pydasm.get_operand_string(i, 2, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
    #
    #             if API_dict1[op_string1] or API_dict2[op_string1]:
    #                 if '[' in op_string1:
    #                     this_api_name = API_dict1[op_string1]
    #                 else:
    #                     this_api_name = API_dict2[op_string1]
    #             elif API_dict1[op_string2] or API_dict2[op_string2]:
    #                 if '[' in op_string2:
    #                     this_api_name = API_dict1[op_string2]
    #                 else:
    #                     this_api_name = API_dict2[op_string2]
    #             elif API_dict1[op_string3] or API_dict2[op_string3]:
    #                 if '[' in op_string3:
    #                     this_api_name = API_dict1[op_string3]
    #                 else:
    #                     this_api_name = API_dict2[op_string3]
    #             del op_string1, op_string2, op_string3
    #             Frequency_dict[this_api_name] += 1
    #         except Exception as e:
    #             pass
    #         # Go to the next instruction
    #         offset += int(i.length)
    #
    # # sorting dictionary by value
    # sorted_dict = sorted(Frequency_dict.items(), key=lambda item:item[1], reverse=True)
    #
    # print('\nwrite DLL_API_Calls_Frequencies.csv ...')
    # # write extracted API calls frequencies
    # with open('./DLL_API_Calls_Frequencies.csv', 'wb') as f:
    #     wr = csv.writer(f)
    #     for key, value in sorted_dict:
    #         wr.writerow([key, value])

    print('\nread DLL_API_Calls_Frequencies.csv ...')
    new_API_LIST = []
    with open('./DLL_API_Calls_Frequencies.csv', 'r') as f_api_ALL:
        lines = csv.reader(f_api_ALL)
        for line in lines:
            if int(line[1]) >= 100:
                new_API_LIST.append(line[0])

    print('\nremove min count API count : len(new_API_LIST) = %d' % len(new_API_LIST))
    DllApiSet_list = os.listdir(DLL_API_SET_PATH)
    DLL_API_dict = {}
    for txt_file in DllApiSet_list:
        with open(os.path.join(DLL_API_SET_PATH, txt_file), 'r') as f:
            lines = f.readlines()
            for line in lines:
                dll_name, api_name = line.split(':')
                api_name = api_name.lstrip(' ').rstrip().split(' ')
                if api_name[0] == '':
                    pass
                else:
                    for api in api_name:
                        if api in new_API_LIST:
                            if dll_name not in DLL_API_dict:
                                DLL_API_dict[dll_name] = []
                            if api not in DLL_API_dict[dll_name]:
                                DLL_API_dict[dll_name].append(api)
                        else:
                            pass
    max_cnt, dll_cnt = 0, 0
    with open('./DLLAPI_matrix.csv', 'wb') as f:
        wr = csv.writer(f)
        for key, item in DLL_API_dict.items():
            if len(item) > max_cnt:
                max_cnt = len(item)
            item.insert(0, key)
            wr.writerow(item)
            dll_cnt += 1
    print('max_cnt = %d' % max_cnt)
    print('dll_cnt = %d' % dll_cnt)




if __name__ == '__main__':
    # 1. Generate TOTAL_DATASET_LABEL and TrainSet, ValidSet, TestSet
    # GenerateDatasetLabel()

    # 2. Generate an Image that doesn't exist in the folder but exists in the label
    # GenerateNoneImg()


    # API_Frequency_calculator()

    # PrintFastTextValue()

    # Dissect_FastText()

    Generate_APIFrequency_DLLAPIMatrix()