import os
import re
import io
import csv
import sys
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
from gensim.models import word2vec
from gensim.models.fasttext import FastText
from pyparsing import Word, hexnums, WordEnd, Optional, alphas, alphanums, SkipTo

def run_opcode_extractor(Dataset_path='', txt_path=''):
    if not os.path.exists(txt_path):
        os.makedirs(txt_path)

    finish_list = os.listdir(txt_path)
    print("extract start!")

    data_list = os.listdir(Dataset_path)
    # extract opcode and APIcalls at trainset
    for file in data_list:
        try:
            check_file_name = file + '.txt'
            print(check_file_name)
            if check_file_name in finish_list:
                print("file = %s  =>  is Finish File... PASS" % check_file_name)
                pass
            else:
                print("file = %s  =>  opcode extract..." % file)
                current_file = os.path.join(Dataset_path, file)  # Address of Dataset to analysis

                pe = pefile.PE(current_file)  # PE open
                # opcode list extract
                open_exe = open(current_file, 'rb')  # open dataset file
                data = open_exe.read()
                EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                raw_size = pe.sections[0].SizeOfRawData
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

                # Start disassembly at the EP
                offset = EntryPoint
                Endpoint = offset + raw_size

                # Loop until the end of the .text section
                with open(os.path.join(txt_path, '%s.txt' % file), 'w') as f_opcode:
                    while offset < Endpoint:
                        # Get the first instruction
                        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                        if not i:
                            break

                        # Print a string representation if the instruction
                        opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
                        f_opcode.write(opcodes + '\n')

                        # Go to the next instruction
                        offset += int(i.length)

                # API list extract
                # API_list = []
                # print("file = " + file)
                # with open(origin_path + '/api/%s.txt' % file, 'w') as f_api:
                #     for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #         for API in entry.imports:
                #             API_list.append(API.name)
                #             f_api.write(str(API.name) + '\n')
                # del API_list

        except Exception as e:
            print("Error! about : " + file)
            print(traceback.format_exc())
            pass


def benign_opcode_extractor(label_file='', Dataset_path='', txt_path=''):
    benign_hash = []
    with open(label_file, 'r') as label_f:
        rdr = csv.reader(label_f)
        for line in rdr:
            hash_name = line[0]
            label = line[1]
            # benign is zero label
            if label == '0':
                benign_hash.append(hash_name.replace('.vir', ''))

    print('len(benign_hash) = %d' % len(benign_hash))

    if not os.path.exists(txt_path):
        os.makedirs(txt_path)

    finish_list = os.listdir(txt_path)
    print("extract start!")

    # extract opcode and APIcalls at trainset
    for benign_hash_file in benign_hash:
        try:
            check_file_name = benign_hash_file + '.txt'
            if check_file_name in finish_list:
                print("file = %s  =>  is Finish File... PASS" % check_file_name)
                pass
            else:
                print("file = %s  =>  opcode extract..." % benign_hash_file)
                current_file = os.path.join(Dataset_path, '%s.vir' % benign_hash_file)  # Address of Dataset to analysis

                pe = pefile.PE(current_file)  # PE open
                # opcode list extract
                open_exe = open(current_file, 'rb')  # open dataset file
                data = open_exe.read()
                EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                raw_size = pe.sections[0].SizeOfRawData
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

                # Start disassembly at the EP
                offset = EntryPoint
                Endpoint = offset + raw_size

                # Loop until the end of the .text section
                with open(os.path.join(txt_path, '%s.txt' % benign_hash_file), 'w') as f_opcode:
                    while offset < Endpoint:
                        # Get the first instruction
                        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                        if not i:
                            break

                        # Print a string representation if the instruction
                        opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
                        f_opcode.write(opcodes + '\n')

                        # Go to the next instruction
                        offset += int(i.length)

                # API list extract
                # API_list = []
                # print("file = " + file)
                # with open(origin_path + '/api/%s.txt' % file, 'w') as f_api:
                #     for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #         for API in entry.imports:
                #             API_list.append(API.name)
                #             f_api.write(str(API.name) + '\n')
                # del API_list

        except Exception as e:
            print("Error! about : " + benign_hash_file)
            print(traceback.format_exc())
            pass


# Extract opcode, API calls, DLL, Byte file, function call, string
# def PEfile_StaticExtractor(file_path, dst_path, label_file):
#     benign_hash, malware_hash = [], []
#     with open(label_file, 'r') as label_f:
#         rdr = csv.reader(label_f)
#         for line in rdr:
#             hash_name = line[0]
#             label = line[1]
#             # benign is '0' label
#             if label == '0':
#                 benign_hash.append(hash_name.replace('.vir', ''))
#             # malware is '1' label
#             elif label == '1':
#                 malware_hash.append(hash_name.replace('.vir', ''))
#
#     print('len(benign_hash) = %d' % len(benign_hash))
#     print('len(malware_hash) = %d' % len(benign_hash))
#
#     if not os.path.exists(dst_path):
#         os.makedirs(dst_path)
#
#     finish_list = os.listdir(dst_path)
#     print("extract start!")
#
#     # extract opcode and APIcalls at trainset
#     for benign_hash_file in benign_hash:
#         try:
#             check_file_name = benign_hash_file + '.txt'
#             if check_file_name in finish_list:
#                 print("file = %s  =>  is Finish File... PASS" % check_file_name)
#                 pass
#             else:
#                 print("file = %s  =>  opcode extract..." % benign_hash_file)
#                 # Address of Dataset to analysis
#                 current_file = os.path.join(file_path, 'benign/%s.vir' % benign_hash_file)
#
#                 pe = pefile.PE(current_file)            # PE file open
#
#                 # opcode list extract
#                 open_exe = open(current_file, 'rb')     # open dataset file
#                 data = open_exe.read()
#                 EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
#                 raw_size = pe.sections[0].SizeOfRawData
#                 EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase
#
#                 # Start disassembly at the EP
#                 offset = EntryPoint
#                 Endpoint = offset + raw_size
#
#                 # Loop until the end of the .text section => OPCODE list extract
#                 with open(os.path.join(dst_path, 'benign/OPCODE/%s.txt' % benign_hash_file), 'w') as f_opcode:
#                     while offset < Endpoint:
#                         # Get the first instruction
#                         i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
#                         if not i:
#                             break
#
#                         # Print a string representation if the instruction
#                         opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
#                         f_opcode.write(opcodes + '\n')
#
#                         # Go to the next instruction
#                         offset += int(i.length)
#
#                 # DLL and API list extract
#                 with open(os.path.join(dst_path, 'benign/DLL_API/%s.txt' % benign_hash_file), 'w') as f_api:
#                     for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                         f_api.write(str(entry.dll) + '\n')
#                         for API in entry.imports:
#                             f_api.write(str(API.name) + '\n')
#
#                 # DLL extract
#                 # Start disassembly at the EP
#                 offset = EntryPoint
#                 Endpoint = offset + raw_size
#                 tcnt, dcnt = 0, 0
#                 for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                     print(entry.dll)
#                     fcnt = 0
#                     dcnt = dcnt + 1
#                     for API in entry.imports:
#                         try:
#                             print(str(API.name) + '\n')
#                             fcnt = fcnt + 1
#                         except Exception as e:
#                             print(traceback.format_exc())
#                             pass
#                         print('import functions : ' + str(fcnt))
#                         tcnt = tcnt + fcnt
#                 print('')
#                 print('import dlls : ' + str(dcnt))
#                 print('total functions : ' + str(tcnt))
#
#                 # function call extract
#
#
#                 # byte files extract
#
#
#                 # string extract
#
#
#
#         except Exception as e:
#             print("Error! about : " + benign_hash_file)
#             print(traceback.format_exc())
#             pass
#
#     return 0


def ASM_BYTE_Classifier(src_path, asm_path, bytes_path):
    data_list = os.listdir(src_path)
    if not os.path.exists(asm_path):
        os.makedirs(asm_path)
    if not os.path.exists(bytes_path):
        os.makedirs(bytes_path)

    for data in data_list:
        file_type = data.split(".")[1]
        if file_type == "asm":
            shutil.move(os.path.join(src_path, data), os.path.join(asm_path, data))
        if file_type == "bytes":
            shutil.move(os.path.join(src_path, data), os.path.join(bytes_path, data))

# Extract about string and generate string image of ASM files
def GenerateStrImg(asm_path, stringImage_dst_path):
    # make directory of string image destination
    if not os.path.exists(stringImage_dst_path):
        os.makedirs(stringImage_dst_path)

    cnt, max_height = 0, 0
    hex_integer = Word(hexnums) + WordEnd()
    str_line = ".data:" + hex_integer + Optional((hex_integer * (1,))) + Optional(Word(alphanums) + ";" + Word(alphanums))

    file_list = os.listdir(asm_path)
    for asm in file_list:
        with io.open(os.path.join(asm_path, asm), 'r', encoding='ISO-8859-1') as f:
            # extract string
            source = f.read()
            lines = source.split('\n')
            string = ''
            string_list = []
            for source_line in lines:
                if (".data:" in source_line[0:6]) and ("db" in source_line):
                    split_list = source_line.split(' ')
                    try:
                        if split_list[-2].encode() == ';':
                            ascii_ = ord(split_list[-1].encode('charmap'))
                            string += str(int(ascii_)) + ' '
                        elif (split_list[-1] == '0') and (string != ''):
                            string_list.append(string)
                            string = ''
                    except Exception as e:
                        pass

            # generate image of string
            try:
                file_size = os.path.getsize(os.path.join(asm_path, asm))
                file_size = file_size / 1024
                if file_size < 10:
                    width = 32
                elif (file_size >= 10) and (file_size < 30):
                    width = 64
                elif (file_size >= 30) and (file_size < 60):
                    width = 128
                elif (file_size >= 60) and (file_size < 100):
                    width = 256
                elif (file_size >= 100) and (file_size < 200):
                    width = 384
                elif (file_size >= 200) and (file_size < 500):
                    width = 512
                elif (file_size >= 500) and (file_size < 1000):
                    width = 784
                else:
                    width = 1024

                mat_list, row_list = [], []
                for line in string_list:
                    new_line = line.rstrip(' ')
                    value_list = new_line.split(' ')
                    value_list.append('0')
                    if (len(value_list)) > width:
                        value_list = value_list[:width]
                    check_value = width - len(row_list)

                    if check_value < len(value_list):
                        mat_list.append(row_list)
                        del row_list
                        row_list = []
                        for value in value_list:
                            row_list.append(value)
                    else:
                        for value in value_list:
                            row_list.append(value)
                mat_list.append(row_list)
                del row_list

                height = len(mat_list)
                if height > max_height:
                    max_height = height
                string_mat = np.zeros((height, width), dtype=np.uint8)
                for y in range(height):
                    for x in range(len(mat_list[y])):
                        string_mat[y][x] = mat_list[y][x]
                img = Image.fromarray(string_mat, 'L')
                img.save(os.path.join(stringImage_dst_path, asm.replace('.asm', '.jpg')))

                cnt += 1
                print('count %d  ||  file name %s finish' % (cnt, asm))

            except Exception as e:
                print(traceback.format_exc())
                pass
    print('max_height = %d' % max_height)


# Extract about DLL-API set
def GenerateDllApiSet(asm_path, DllApiSet_dst_path):
    # make directory of DLL-APIset destination
    if not os.path.exists(DllApiSet_dst_path):
        os.makedirs(DllApiSet_dst_path)

    # extract DLL-API in idata section and generate DLL-API set(txt file)
    hex_integer = Word(hexnums) + WordEnd()
    DLL_line = ".idata:" + hex_integer + ";" + "Imports from" + Word(alphanums + '.' + '_')("dll")
    API_line = ".idata:" + hex_integer + ";" + Word(alphanums)("type") + Word(alphanums + '_' + '*')("call") + Word(alphanums + '_')("API") + '('
    DLL_list, API_list = [], []
    cnt = 0
    file_list = os.listdir(asm_path)
    for asm in file_list:
        with io.open(os.path.join(asm_path, asm), 'r', encoding='ISO-8859-1') as f:
            # extract DLL-API in idata section
            source = f.read()
            lines = source.split('\n')
            DllApi_dict = {}
            now_DLL = ''
            for source_line in lines:
                # extract DLL
                try:
                    result = DLL_line.parseString(source_line)
                    if "dll" in result:
                        now_DLL = str(result.dll).replace('.DLL', 'dll')
                        if now_DLL not in DLL_list:
                            DLL_list.append(now_DLL)

                        if now_DLL in DllApi_dict:
                            pass
                        else:
                            DllApi_dict[now_DLL] = []
                except Exception as e:
                    pass

                # extract Function calls
                try:
                    result = API_line.parseString(source_line)
                    if "API" in result:
                        if str(result.API) not in API_list:
                            API_list.append(str(result.API))
                        DllApi_dict[now_DLL].append(str(result.API))
                except Exception as e:
                    pass

            # make DLL-API set of this filename assembly code
            with open(os.path.join(DllApiSet_dst_path, '%s.txt' % asm.replace('.asm', '')), 'w') as f_dll:
                try:
                    for key, value in DllApi_dict.items():
                        f_dll.write('%s:' % key)
                        try:
                            for i in range(len(value)):
                                f_dll.write(' %s' % value[i])
                        except Exception as e:
                            pass
                        f_dll.write('\n')
                except Exception as e:
                    pass

            cnt += 1
        print('count %d  ||  file name %s finish' % (cnt, asm))

    with open('./DLL_LIST.txt', 'w') as f_dll_ALL:
        for value in DLL_list:
            f_dll_ALL.write('%s ' % value)
    with open('./API_LIST.txt', 'w') as f_api_ALL:
        for value in API_list:
            f_api_ALL.write('%s ' % value)


# Extract about DLL-API image of ASM files
def GenerateDllApiImg(asm_path, DllApiSet_dst_path, DllApiImage_dst_path):
    with open('./DLL_LIST.txt', 'r') as f_dll_ALL:
        line = f_dll_ALL.readline()
        DLL_LIST = line.rstrip(' ').split(' ')
    with open('./API_LIST.txt', 'r') as f_api_ALL:
        line = f_api_ALL.readline()
        API_LIST = line.rstrip(' ').split(' ')

    # make directory of DLL-API image destination
    if not os.path.exists(DllApiImage_dst_path):
        os.makedirs(DllApiImage_dst_path)

    hex_integer = Word(hexnums) + WordEnd()
    APIcalls_line = ".text:" + hex_integer + Optional((hex_integer * (1,))) + Word(alphas) + Optional(Word("ds:" + alphanums)("api"))
    DLLAPISet_list = os.listdir(DllApiSet_dst_path)
    cnt = 0
    for txt_file in DLLAPISet_list:
        with open(os.path.join(DllApiSet_dst_path, txt_file), 'r') as f_txt:
            DllApi_dict = {}
            this_file_API_list = []
            lines = f_txt.readlines()
            for line in lines:
                dll_name, API_names = line.split(':')
                API_names = API_names.lstrip(' ')
                API_names = API_names.rstrip('\n')
                if API_names:
                    DllApi_dict[dll_name] = API_names.split(' ')
                    for this_api in DllApi_dict[dll_name]:
                        if this_api not in this_file_API_list:
                            this_file_API_list.append(this_api)
                else:
                    DllApi_dict[dll_name] = []

        try:
            DLL_API_matrix = np.zeros((len(DLL_LIST), len(API_LIST)), dtype=np.uint8)
            with io.open(os.path.join(asm_path, txt_file.replace('.txt', '.asm')), 'r', encoding='ISO-8859-1') as f:
                # extract DLL-API in idata section
                source = f.read()
                lines = source.split('\n')
                for source_line in lines:
                    # extract API calls
                    try:
                        result = APIcalls_line.parseString(source_line)
                        if "api" in result:
                            APIname = str(result.api)
                            if APIname.find("ds:") != -1:
                                APIname = APIname.replace("ds:", "")

                            if APIname in this_file_API_list:
                                for key, value in DllApi_dict.items():
                                    if APIname in value:
                                        y = DLL_LIST.index(key)
                                        x = API_LIST.index(APIname)
                                        if DLL_API_matrix[y][x] == 255:
                                            pass
                                        else:
                                            DLL_API_matrix[y][x] += 1
                    except Exception as e:
                        pass

            img = Image.fromarray(DLL_API_matrix, 'L')
            img.save(os.path.join(DllApiImage_dst_path, txt_file.replace('.txt', '.jpg')))
            del DLL_API_matrix

            cnt += 1
            print('count %d  ||  file name %s finish' % (cnt, txt_file))
        except Exception as e:
            pass


# Extract about opcode, API and generate opcode, API set
def GenerateOpcodeApiSet(asm_path, OpcodeSet_dst_path, ApiSet_dst_path):
    # make directory of opcode and API Set destination
    if not os.path.exists(OpcodeSet_dst_path):
        os.makedirs(OpcodeSet_dst_path)
    if not os.path.exists(ApiSet_dst_path):
        os.makedirs(ApiSet_dst_path)

    with open('./API_LIST.txt', 'r') as f_api_ALL:
        line = f_api_ALL.readline()
        API_LIST = line.rstrip(' ').split(' ')

    # extract and generate Opcode, API Set
    hex_integer = Word(hexnums) + WordEnd()
    op_line = ".text:" + hex_integer + Optional((hex_integer * (1,))("instructions") + Word(alphas, alphanums)("opcode"))
    API_line = ".text:" + hex_integer + Optional((hex_integer * (1,))) + Word(alphas) + Optional(Word("ds:" + alphanums)("api"))
    cnt = 0
    file_list = os.listdir(asm_path)
    for asm in file_list:
        cnt += 1
        print('count %d  ||  open %s...' % (cnt, asm))
        with io.open(os.path.join(asm_path, asm), 'r', encoding='ISO-8859-1') as f:
            # extract DLL-API in idata section
            source = f.read()
            lines = source.split('\n')
            opcodelist, apilist = [], []
            now_opcode, now_api = '', ''
            opcode_len_limit, API_len_limit = 600, 600
            opcode_len_cnt, API_len_cnt = 0, 0
            for source_line in lines:
                # extract opcode
                try:
                    if opcode_len_cnt >= opcode_len_limit:
                        pass
                    else:
                        result = op_line.parseString(source_line)
                        if "opcode" in result:
                            if (result.opcode.islower()) and (now_opcode != result.opcode):
                                now_opcode = result.opcode
                                opcodelist.append(now_opcode)
                                opcode_len_cnt += 1
                except Exception as e:
                    pass

                # extract API calls in API list
                try:
                    if API_len_cnt >= API_len_limit:
                        pass
                    else:
                        result = API_line.parseString(source_line)
                        if "api" in result:
                            APIname = str(result.api)
                            if APIname.find("ds:") != -1:
                                APIname = APIname.replace("ds:", "")

                            if (APIname in API_LIST) and (now_api != APIname):
                                now_api = APIname
                                apilist.append(now_api)
                                API_len_cnt += 1

                except Exception as e:
                    pass

        # make opcode set of this filename assembly code
        with open(os.path.join(OpcodeSet_dst_path, '%s.txt' % asm.replace('.asm', '')), 'w') as f_opcode:
            try:
                for opcode in opcodelist:
                    f_opcode.write(opcode + '\n')
            except Exception as e:
                pass

        # make API set of this filename assembly code
        with open(os.path.join(ApiSet_dst_path, '%s.txt' % asm.replace('.asm', '')), 'w') as f_api:
            try:
                for api in apilist:
                    f_api.write(api + '\n')
            except Exception as e:
                pass


def Generate_FastText_TrainSet(src_path, FastText_path, data_type='OPCODE'):
    if not os.path.exists(FastText_path):
        os.makedirs(FastText_path)
    try:
        # make all_data.txt file
        all_data_element = open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % data_type), 'a')

        file_list = os.listdir(src_path)
        print('file count = %d' % len(file_list))
        for txt_file in file_list:
            md5_hash = txt_file
            if md5_hash.find(".txt") != -1:
                md5_hash = md5_hash.replace(".txt", "")
            if md5_hash.find("VirusShare_") != -1:
                md5_hash = md5_hash.replace("VirusShare_", "")

            with open(os.path.join(src_path, txt_file), 'r') as f:
                lines = f.readlines()

                all_data_element.write(md5_hash + '##')
                for line in lines:
                    elem_name = line
                    if elem_name.find("?") != -1:
                        elem_name = elem_name.replace("?", "")
                    if elem_name.find(" ") != -1:
                        elem_name = elem_name.replace(" ", "")
                    if elem_name.find("\n") != -1:
                        elem_name = elem_name.replace("\n", "")

                    all_data_element.write(elem_name.strip() + ' ')
                del lines
                all_data_element.write('\n')

        all_data_element.close()
    except Exception as e:
        print(traceback.format_exc())
        pass


def label_del(FastText_path, name='OPCODE'):
    train_label = open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % name), 'r')
    train_label_lines = train_label.readlines()
    save = open(os.path.join(FastText_path, '%s_FastText_train.txt' % name), 'w')
    for line in train_label_lines:
        try:
            contents = line.split('##')[1]
            save.write(contents + '\n')
        except Exception as e:
            print(traceback.format_exc())
            pass
    train_label.close()
    save.close()


def train_FastText(FastText_path, name='OPCODE', total_exam=500):
    models_path = os.path.join(FastText_path, 'models')
    if not os.path.exists(models_path):
        os.makedirs(models_path)

    logging.basicConfig(format='%(asctime)s:%(levelname)s: %(message)s', level=logging.INFO)
    sentences = word2vec.Text8Corpus(os.path.join(FastText_path, '%s_FastText_train.txt' % name))

    print("\nStart ==> FastText 64 Vector Size train\n")
    FT64_model = FastText(sg=0, hs=1, size=64, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
    FT64_model.build_vocab(sentences)
    FT64_model.train(sentences, total_examples=total_exam, epochs=100)
    FT64_model.save(os.path.join(models_path, '%s_64size' % name))
    print("\nFinish ==> FastText 64 Vector Size train\n")
    del FT64_model

    print("\nStart ==> FastText 128 Vector Size train\n")
    FT128_model = FastText(sg=0, hs=1, size=128, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
    FT128_model.build_vocab(sentences)
    FT128_model.train(sentences, total_examples=total_exam, epochs=100)
    FT128_model.save(os.path.join(models_path, '%s_128size' % name))
    print("\nFinish ==> FastText 128 Vector Size train\n")
    del FT128_model

    print("\nStart ==> FastText 256 Vector Size train\n")
    FT256_model = FastText(sg=0, hs=1, size=256, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
    FT256_model.build_vocab(sentences)
    FT256_model.train(sentences, total_examples=total_exam, epochs=100)
    FT256_model.save(os.path.join(models_path, '%s_256size' % name))
    print("\nFinish ==> FastText 256 Vector Size train\n")
    del FT256_model

    print("\nStart ==> FastText 512 Vector Size train\n")
    FT512_model = FastText(sg=0, hs=1, size=512, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
    FT512_model.build_vocab(sentences)
    FT512_model.train(sentences, total_examples=total_exam, epochs=100)
    FT512_model.save(os.path.join(models_path, '%s_512size' % name))
    print("\nFinish ==> FastText 512 Vector Size train\n")
    del FT512_model


def GenerateFastTextImg(FastText_path, img_base_dir, name='', embedding_size=512):
    FastText_file = os.path.join(FastText_path, 'models/%s_%ssize' % (name, embedding_size))
    FastText_model = FastText.load(FastText_file)

    words = []
    for i in range(len(FastText_model.wv.vocab)):
        words.append(FastText_model.wv.index2word[i])

    embedding_matrix = np.zeros((len(words), embedding_size))
    embedding_vector_dict = {}
    for i in range(len(words)):
        if words[i] in FastText_model.wv.vocab:
            embedding_vector_list = FastText_model.wv[words[i]].tolist()
            embedding_vector_dict[words[i]] = embedding_vector_list
            embedding_vector = FastText_model.wv[words[i]]
            embedding_matrix[i] = embedding_vector
    max_value = embedding_matrix.max()
    min_value = embedding_matrix.min()

    for key in embedding_vector_dict:
        value_list = embedding_vector_dict[key]
        for cnt in range(len(value_list)):
            embedding_vector_dict[key][cnt] = int(255 * ((value_list[cnt] - min_value) / (max_value - min_value)))

    img_dst_path = os.path.join(img_base_dir, '%s' % embedding_size)
    if not os.path.exists(img_dst_path):
        os.makedirs(img_dst_path)
    with open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % name), 'r') as f:
        lines = f.readlines()
        for line in lines:
            label, contents = line.split('##')
            contents_list = contents.rstrip().split(' ')
            height = len(contents_list)
            mat = np.zeros((height, embedding_size), dtype=np.uint8)
            for y in range(height):
                embedding_vector_list = embedding_vector_dict[contents_list[y]]
                x = 0
                for x_value in embedding_vector_list:
                    mat[y][x] = x_value
                    x += 1
            img = Image.fromarray(mat, 'L')
            img.save(os.path.join(img_dst_path, '%s.jpg' % label))





# def LABEL_Classifier(asm_path, bytes_path, label_file):
#     if not os.path.exists(asm_path):
#         os.makedirs(asm_path)
#     if not os.path.exists(bytes_path):
#         os.makedirs(bytes_path)
#     for i in range(10):
#         os.makedirs(os.path.join(asm_path, str(i+1)))
#         os.makedirs(os.path.join(bytes_path, str(i+1)))
#
#     label_dict = {}
#     with open(label_file, 'r') as f:
#         rdr = csv.reader(f)
#         for line in rdr:
#             if line[0] == 'Id':
#                 pass
#             else:
#                 label_dict['%s.asm' % line[0]] = line[1]
#                 label_dict['%s.bytes' % line[0]] = line[1]
#     for data in data_list:
#         file_type = data.split(".")[1]
#         label = label_dict[data]
#         if file_type == "asm":
#             shutil.move(os.path.join(src_path, data), os.path.join(asm_path, '%s/%s' % (label, data)))
#         if file_type == "bytes":
#             shutil.move(os.path.join(src_path, data), os.path.join(bytes_path, '%s/%s' % (label, data)))


if __name__ == '__main__':
    DATA_SRC_PATH = 'C://Users/Ucloud/Downloads/malware-classification/train'
    ASM_SRC_PATH = 'C://Users/Ucloud/Downloads/malware-classification/asm_files'
    Test_ASM_SRC_PATH = './dataset/test'
    BYTES_SRC_PATH = 'C://Users/Ucloud/Downloads/malware-classification/bytes_files'
    LABEL_FILE = './dataset/trainLabels.csv'
    TRAIN_FEATURE_PATH = './dataset/features'

    OPCODE_SET_PATH = os.path.join(TRAIN_FEATURE_PATH, 'opcode')
    API_SET_PATH = os.path.join(TRAIN_FEATURE_PATH, 'Api')
    DLL_API_SET_PATH = os.path.join(TRAIN_FEATURE_PATH, 'DllApi')
    FASTTEXT_BASE_DIR = './dataset/FastText'

    DLL_API_IMG_PATH = os.path.join(TRAIN_FEATURE_PATH, 'DllApiImg')
    STRING_IMG_PATH = os.path.join(TRAIN_FEATURE_PATH, 'stringImg')
    OPCODE_IMG_PATH = os.path.join(TRAIN_FEATURE_PATH, 'opcodeImg')
    API_IMG_PATH = os.path.join(TRAIN_FEATURE_PATH, 'ApiImg')

    # 0
    # ASM_BYTE_Classifier(DATA_SRC_PATH, ASM_SRC_PATH, BYTES_SRC_PATH)

    # 1
    # GenerateStrImg(ASM_SRC_PATH, STRING_IMG_PATH)

    # 2
    # GenerateDllApiSet(ASM_SRC_PATH, DLL_API_SET_PATH)
    # GenerateDllApiImg(ASM_SRC_PATH, DLL_API_SET_PATH, DLL_API_IMG_PATH)

    # 3
    # GenerateOpcodeApiSet(ASM_SRC_PATH, OPCODE_SET_PATH, API_SET_PATH)
    #
    # Generate_FastText_TrainSet(OPCODE_SET_PATH, FASTTEXT_BASE_DIR, data_type='OPCODE')
    # label_del(FASTTEXT_BASE_DIR, name='OPCODE')
    # Generate_FastText_TrainSet(API_SET_PATH, FASTTEXT_BASE_DIR, data_type='API')
    # label_del(FASTTEXT_BASE_DIR, name='API')
    #
    # train_FastText(FASTTEXT_BASE_DIR, name='OPCODE', total_exam=10868)
    # train_FastText(FASTTEXT_BASE_DIR, name='API', total_exam=10868)
    #
    # embedding_list = [64, 128, 256, 512]
    # for size in embedding_list:
    #     GenerateFastTextImg(FASTTEXT_BASE_DIR, OPCODE_IMG_PATH, name='OPCODE', embedding_size=size)
    #     GenerateFastTextImg(FASTTEXT_BASE_DIR, API_IMG_PATH, name='API', embedding_size=size)





    # LABEL_Classifier(ASM_SRC_PATH, BYTES_SRC_PATH, LABEL_FILE)