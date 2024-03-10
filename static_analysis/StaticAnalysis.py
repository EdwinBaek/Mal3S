import os
import re
import io
import csv
import sys
import json
import math
import time
import string
import struct
import codecs
import base64
import shutil
import logging
import binascii
import datetime
import traceback
import numpy as np
from PIL import Image

import pydasm
import pefile
# from pydbg import *
# from pydbg.defines import *

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
                now_opcode = ''
                # Loop until the end of the .text section
                with open(os.path.join(txt_path, '%s.txt' % file), 'w') as f_opcode:
                    while offset < Endpoint:
                        # Get the first instruction
                        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                        if not i:
                            break

                        # Print a string representation if the instruction
                        opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
                        if now_opcode != opcodes:
                            f_opcode.write(opcodes + '\n')
                        now_opcode = opcodes

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


def KISA_LABEL_Classifier(src_path, mal_path, ben_path, label_file):
    if not os.path.exists(mal_path):
        os.makedirs(mal_path)
    if not os.path.exists(ben_path):
        os.makedirs(ben_path)

    with io.open(label_file, 'r', encoding='utf-8-sig') as f:
        rdr = csv.reader(f)
        for line in rdr:
            hash_name = line[0]
            label = line[1]
            # benign is zero label
            if label == '0':
                shutil.move(os.path.join(src_path, '%s' % hash_name), os.path.join(ben_path, '%s' % hash_name))
            # malware is one label
            elif label == '1':
                shutil.move(os.path.join(src_path, '%s' % hash_name), os.path.join(mal_path, '%s' % hash_name))


# Extract opcode, API calls, DLL, Byte file, function call, string
def PEfile_StaticExtractor(file_path, dst_path, label_file):
    benign_hash, malware_hash = [], []
    with open(label_file, 'r') as label_f:
        rdr = csv.reader(label_f)
        for line in rdr:
            hash_name = line[0]
            label = line[1]
            # benign is '0' label
            if label == '0':
                benign_hash.append(hash_name.replace('.vir', ''))
            # malware is '1' label
            elif label == '1':
                malware_hash.append(hash_name.replace('.vir', ''))

    print('len(benign_hash) = %d' % len(benign_hash))
    print('len(malware_hash) = %d' % len(benign_hash))

    OPCODE_FEATURE_PATH = os.path.join(dst_path, 'opcode')
    API_FEATURE_PATH = os.path.join(dst_path, 'Api')
    DLL_API_SET_PATH = os.path.join(dst_path, 'DllApi')
    STRING_SET_PATH = os.path.join(dst_path, 'string')
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)
        os.makedirs(OPCODE_FEATURE_PATH)
        os.makedirs(API_FEATURE_PATH)
        os.makedirs(DLL_API_SET_PATH)
        os.makedirs(STRING_SET_PATH)

    finish_list = os.listdir(dst_path)
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
                # Address of Dataset to analysis
                current_file = os.path.join(file_path, '%s.vir' % benign_hash_file)

                # PE file and file(bytes) open
                pe = pefile.PE(current_file)
                open_exe = open(current_file, 'rb')
                data = open_exe.read()

                EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                raw_size = pe.sections[0].SizeOfRawData
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

                # pydbg open
                # dbg = pydbg()
                # dbg.load(current_file)

                # global pe, DllName, func_name, open_exe

                # dbg_entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                # dbg.bp_set(dbg_entrypoint, handler=entryhandler)
                raw_size = pe.sections[0].SizeOfRawData
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase


                # Start disassembly at the EP
                offset = EntryPoint
                Endpoint = offset + raw_size

                for section in pe.sections:
                    if '.text' in str(section.Name):
                        print(section.PointerToRawData)
                        print(section.Misc_VirtualSize)
                        # entry = section.PointerToRawData - 1
                        # end = section.SizeOfRawData + entry
                        # raw_data = pe.__data__[entry:end]
                        # print(raw_data.decode())
                        # data = np.frombuffer(raw_data, dtype=np.float32)
                        # print(data)
                sys.exit()

                # # Loop until the end of the .text section => OPCODE list extract
                # with open(os.path.join(OPCODE_FEATURE_PATH, '%s.txt' % benign_hash_file), 'w') as f_opcode:
                #     now_opcode = ''
                #     opcodelist = []
                #     opcode_len_limit = 600
                #     opcode_len_cnt = 0
                #     while offset < Endpoint:
                #         # Get the first instruction
                #         i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                #         if not i:
                #             break
                #
                #         opcode_1 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset)
                #         opcode_2 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset)
                #         opcode_3 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset)
                #         register_1 = pydasm.get_register_type(0)
                #         register_2 = pydasm.get_register_type(1)
                #         register_3 = pydasm.get_register_type(2)
                #         line = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, EntryPoint_va + offset)
                #         print('=' * 50)
                #         print(opcode_1)
                #         print(opcode_2)
                #         print(opcode_3)
                #         print(register_1)
                #         print(register_2)
                #         print(register_3)
                #
                #
                #         offset += int(i.length)
                #
                #         # Print a string representation if the instruction
                #         opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
                #         opcodes = opcodes.split(' ')[0]
                #         if (now_opcode != opcodes) and (opcode_len_cnt < opcode_len_limit):
                #             now_opcode = opcodes
                #             opcodelist.append(now_opcode)
                #             opcode_len_cnt += 1
                #         if opcode_len_cnt == opcode_len_limit:
                #             break
                #         # Go to the next instruction
                #         offset += int(i.length)
                #     # write opcode set
                #     try:
                #         for op in opcodelist:
                #             f_opcode.write(op + '\n')
                #     except Exception as e:
                #         pass

                # for line in pe.sections[0]:
                #     print(line)
                # sys.exit()
                #


                # # DLL and API list extract
                # with open(os.path.join(DLL_API_SET_PATH, '%s.txt' % benign_hash_file), 'w') as f_api:
                #     for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #         DLL_name = str(entry.dll).replace('.DLL', '.dll')
                #         print('================== DLL_name ==================')
                #         print(DLL_name)
                #         # f_api.write('%s:' % DLL_name)
                #         for API in entry.imports:
                #             API_name = str(API.name)
                #             print(API_name)
                #             print(API_name.encode("hex"))
                #             # f_api.write(' %s' % API_name)
                #                 #
                #                 #     for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                #                 #         print('exp.name = %s' % exp.name)


                # # from Ero Carrera's blog
                # for fileinfo in pe.FileInfo:
                #     if fileinfo.Key == 'StringFileInfo':
                #         for st in fileinfo.StringTable:
                #             for entry in st.entries.items():
                #                 print(entry)
                # sys.exit()

                # for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                #     if not exp.name:
                #         name = ord(exp.ordinal)
                #     else:
                #         name = exp.name
                #     print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), name, exp.ordinal)

                # for exp in pe.DIRECTORY_ENTRY_IMPORT:
                #     if not exp.name:
                #         name = ord(exp.ordinal)
                #     else:
                #         name = exp.name
                #     print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), name, exp.ordinal)


                # # DLL extract
                # # Start disassembly at the EP
                # offset = EntryPoint
                # Endpoint = offset + raw_size
                # tcnt, dcnt = 0, 0
                # for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #     print(entry.dll)
                #     fcnt = 0
                #     dcnt = dcnt + 1
                #     for API in entry.imports:
                #         try:
                #             print(bytes(API.name), str(API.name) + '\n')
                #             fcnt = fcnt + 1
                #         except Exception as e:
                #             print(traceback.format_exc())
                #             pass
                #         print('import functions : ' + str(fcnt))
                #         tcnt = tcnt + fcnt
                # print('')
                # print('import dlls : ' + str(dcnt))
                # print('total functions : ' + str(tcnt))

                # function call extract


                # byte files extract


                # string extract



        except Exception as e:
            print("Error! about : " + benign_hash_file)
            print(traceback.format_exc())
            pass

    return 0


# Copy Benign PEfile using API set and String Image
def CopyBenignDataset(src_path, feature_path, dst_path, data_number=1208):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)
    API_PATH = os.path.join(feature_path, 'Api')
    API_AWAY_PATH = os.path.join(feature_path, 'ApiTEMP')
    if not os.path.exists(API_AWAY_PATH):
        os.makedirs(API_AWAY_PATH)
    API_feature_list = os.listdir(API_PATH)

    for data_cnt in range(len(API_feature_list)):
        if data_cnt < data_number:
            # copy Benign PEfile
            shutil.copy(os.path.join(src_path, API_feature_list[data_cnt].replace('.txt', '.vir')),
                        os.path.join(dst_path, API_feature_list[data_cnt].replace('.txt', '.vir')))
        else:
            shutil.move(os.path.join(API_PATH, API_feature_list[data_cnt]),
                        os.path.join(API_AWAY_PATH, API_feature_list[data_cnt]))


# def ASM_BYTE_Classifier(src_path, asm_path, bytes_path):
#     data_list = os.listdir(src_path)
#     if not os.path.exists(asm_path):
#         os.makedirs(asm_path)
#     if not os.path.exists(bytes_path):
#         os.makedirs(bytes_path)
#
#     for data in data_list:
#         file_type = data.split(".")[1]
#         if file_type == "asm":
#             shutil.move(os.path.join(src_path, data), os.path.join(asm_path, data))
#         if file_type == "bytes":
#             shutil.move(os.path.join(src_path, data), os.path.join(bytes_path, data))
#
#
# def StaticAnalysis(file_path, dst_path):
#     # extract opcode, API calls, string, DLL-FunctionCall and generate dataset
#     # opcode and API calls dataset for FastText train (.txt file)
#     # string and DLL-FunctionCall dataset for Generate image (.txt file)
#     def ASMFeatureExtractor(source, dst_path, filename):
#         hex_integer = Word(hexnums) + WordEnd()
#         op_line = ".text:" + hex_integer + Optional(
#             (hex_integer * (1,))("instructions") + Word(alphas, alphanums)("opcode"))
#         api_line = ".text:" + hex_integer + Optional((hex_integer * (1,))) + "call" + Optional(Word("ds:" + alphanums)("api"))
#         opcodelist, apilist = [], []
#         now_opcode, now_api = '', ''
#         opcode_len_limit, api_len_limit = 600, 600
#         opcode_len_cnt, api_len_cnt = 0, 0
#
#         dll_line = ".idata:" + hex_integer + ";" + "Imports from" + Word(alphanums + '.' + '_')("dll")
#         func_line = ".idata:" + hex_integer + ";" + Word(alphanums)("type") + Word(alphanums + '_')("call") + Word(
#             alphanums + '_')("func") + '('
#         DllFunc_dict = {}
#         now_DLL = ''
#
#         str_line1 = ".rdata:" + hex_integer + Optional(
#             (hex_integer * (1,))) + ";" + Word(alphanums + ' ' + '(' + ')' + "'" + '@' + '*' + ':' + ';' + '.' + '_')("str1")
#         str_line2 = ".data:" + hex_integer + Optional(
#             (hex_integer * (1,))) + ";" + Word(alphanums + ' ' + '(' + ')' + "'" + '@' + '*' + ':' + ';' + '.' + '_')("str2")
#         strlist = []
#         str1_len_limit, str2_len_limit = 500, 500
#         str1_len_cnt, str2_len_cnt = 0, 0
#
#         lines = source.split('\n')
#         for source_line in lines:
#             # extract opcode
#             try:
#                 if opcode_len_cnt >= opcode_len_limit:
#                     pass
#                 else:
#                     result = op_line.parseString(source_line)
#                     if "opcode" in result:
#                         if (result.opcode.islower()) and (now_opcode != result.opcode):
#                             now_opcode = result.opcode
#                             opcodelist.append(now_opcode)
#                             opcode_len_cnt += 1
#             except Exception as e:
#                 pass
#
#             # extract API calls
#             try:
#                 if api_len_cnt >= api_len_limit:
#                     pass
#                 else:
#                     result = api_line.parseString(source_line)
#                     if "api" in result:
#                         APIname = result.api
#                         APIname = APIname.replace("ds:", "")
#                         APIname = APIname.replace("__", "")
#                         if (len(APIname) > 3) and ("sub" not in APIname) and ("dword" not in APIname) and (now_api != APIname):
#                             now_api = APIname
#                             apilist.append(now_api)
#                             api_len_cnt += 1
#             except Exception as e:
#                 pass
#
#             # extract DLL
#             try:
#                 result = dll_line.parseString(source_line)
#                 if "dll" in result:
#                     now_DLL = result.dll
#                     if now_DLL in DllFunc_dict:
#                         pass
#                     else:
#                         DllFunc_dict[now_DLL] = []
#             except Exception as e:
#                 pass
#
#             # extract Function calls
#             try:
#                 result = func_line.parseString(source_line)
#                 if "func" in result:
#                     DllFunc_dict[now_DLL].append(result.func)
#             except Exception as e:
#                 pass
#
#             # extract string in rdata str_line1
#             try:
#                 if str1_len_cnt >= str1_len_limit:
#                     pass
#                 else:
#                     result = str_line1.parseString(source_line)
#                     if ("str1" in result) and (str1_len_cnt < str1_len_limit):
#                         strlist.append(result.str1)
#                         str1_len_cnt += 1
#             except Exception as e:
#                 pass
#
#             # extract string in data str_line2
#             try:
#                 if str2_len_cnt >= str2_len_limit:
#                     pass
#                 else:
#                     result = str_line2.parseString(source_line)
#                     if ("str2" in result) and (str2_len_cnt < str2_len_limit):
#                         strlist.append(result.str2)
#                         str2_len_cnt += 1
#             except Exception as e:
#                 pass
#
#         # make directory of opcode destination
#         opcode_path = os.path.join(dst_path, 'opcode')
#         if not os.path.exists(opcode_path):
#             os.makedirs(opcode_path)
#         # make opcode set of this filename assembly code
#         with open(os.path.join(opcode_path, '%s.txt' % filename.replace('.asm', '')), 'a') as f_opcode:
#             for opcode in opcodelist:
#                 f_opcode.write(opcode + '\n')
#
#         # make directory of API calls destination
#         api_path = os.path.join(dst_path, 'APIcalls')
#         if not os.path.exists(api_path):
#             os.makedirs(api_path)
#         # make opcode set of this filename assembly code
#         with open(os.path.join(api_path, '%s.txt' % filename.replace('.asm', '')), 'w') as f_api:
#             try:
#                 for api in apilist:
#                     f_api.write(api + '\n')
#             except Exception as e:
#                 pass
#
#         # make directory of string destination
#         str_path = os.path.join(dst_path, 'string')
#         if not os.path.exists(str_path):
#             os.makedirs(str_path)
#         # make opcode set of this filename assembly code
#         with open(os.path.join(str_path, '%s.txt' % filename.replace('.asm', '')), 'w') as f_str:
#             try:
#                 for str in strlist:
#                     for char_ in str:
#                         tmp = int(ord(char_))
#                         f_str.write('%s ' % tmp)
#                     f_str.write('\n')
#             except Exception as e:
#                 pass
#
#         # make directory of DLL-FuncCall destination
#         dll_path = os.path.join(dst_path, 'DllFunc')
#         if not os.path.exists(dll_path):
#             os.makedirs(dll_path)
#         # make opcode set of this filename assembly code
#         with open(os.path.join(dll_path, '%s.txt' % filename.replace('.asm', '')), 'w') as f_dll:
#             try:
#                 for key, value in DllFunc_dict.items():
#                     f_dll.write('%s:' % key)
#                     try:
#                         for i in range(len(value)):
#                             f_dll.write(' %s' % value[i])
#                     except Exception as e:
#                         pass
#                     f_dll.write('\n')
#             except Exception as e:
#                 pass
#
#     # Generate DLL-FunctionCall image
#     def GenerateDllFuncImg(DllFunc_path, dst_path):
#         # make directory of DLL-FunctionCall image destination
#         if not os.path.exists(dst_path):
#             os.makedirs(dst_path)
#
#         DllFunc_txt_list = os.listdir(DllFunc_path)
#         DLL_list, Func_list = [], []
#         for txt_file in DllFunc_txt_list:
#             with open(os.path.join(DllFunc_path, txt_file), 'r') as f:
#                 lines = f.readlines()
#                 for line in lines:
#                     DLL_name = line.split(':')[0].replace(".dll", ".DLL")
#                     if DLL_name not in DLL_list:
#                         DLL_list.append(DLL_name)
#                     else:
#                         pass
#                     FuncCalls = line.split(':')[1].lstrip(' ').rstrip('\n').split(' ')
#                     for Func in FuncCalls:
#                         if Func not in Func_list:
#                             Func_list.append(Func)
#                         else:
#                             pass
#
#         for txt_file in DllFunc_txt_list:
#             with open(os.path.join(DllFunc_path, txt_file), 'r') as f:
#                 lines = f.readlines()
#                 mat = np.zeros((len(DLL_list), len(Func_list)), dtype=int)
#                 for line in lines:
#                     DLL_name = line.split(':')[0].replace(".dll", ".DLL")
#                     if DLL_name not in DLL_list:
#                         DLL_list.append(DLL_name)
#                     x_value = DLL_list.index(DLL_name)
#                     FuncCalls = line.split(':')[1].lstrip(' ').rstrip('\n').split(' ')
#                     for Func in FuncCalls:
#                         if Func not in Func_list:
#                             Func_list.append(Func)
#                         y_value = Func_list.index(Func)
#                         mat[x_value][y_value] += 1
#             img = Image.fromarray(mat)
#             img.save(os.path.join(dst_path, txt_file.replace('.txt', '.png')))
#
#     # Generate String image
#     def GenerateStrImg(Str_path, ASM_src_path, dst_path):
#         # make directory of String image destination
#         if not os.path.exists(dst_path):
#             os.makedirs(dst_path)
#
#         str_txt_list = os.listdir(Str_path)
#         for txt_file in str_txt_list:
#             try:
#                 file_size = os.path.getsize(os.path.join(ASM_src_path, txt_file.replace('.txt', '.asm')))
#                 file_size = file_size / 1024
#                 if file_size < 10:
#                     width = 32
#                 elif (file_size >= 10) and (file_size < 30):
#                     width = 64
#                 elif (file_size >= 30) and (file_size < 60):
#                     width = 128
#                 elif (file_size >= 60) and (file_size < 100):
#                     width = 256
#                 elif (file_size >= 100) and (file_size < 200):
#                     width = 384
#                 elif (file_size >= 200) and (file_size < 500):
#                     width = 512
#                 elif (file_size >= 500) and (file_size < 1000):
#                     width = 784
#                 else:
#                     width = 1024
#                 max_line = 1
#                 mat_list = []
#                 with open(os.path.join(Str_path, txt_file), 'r') as f:
#                     # print(txt_file)
#                     lines = f.readlines()
#                     row_list = []
#                     for line in lines:
#                         new_line = line.rstrip(' \n')
#                         value_list = new_line.split(' ')
#                         value_list.append('0')
#                         check_value = width - len(row_list)
#
#                         if check_value < len(value_list):
#                             max_line += 1
#                             mat_list.append(row_list)
#                             del row_list
#                             row_list = []
#                             for value in value_list:
#                                 row_list.append(value)
#                         else:
#                             for value in value_list:
#                                 row_list.append(value)
#
#                 if max_line < 2:
#                     string_mat = np.zeros((max_line, width), dtype=int)
#                     for x in range(len(row_list)):
#                         string_mat[0][x] = row_list[x]
#                 else:
#                     height = len(mat_list)
#                     string_mat = np.zeros((height, width), dtype=int)
#                     for y in range(height):
#                         for x in range(len(mat_list[y])):
#                             string_mat[y][x] = mat_list[y][x]
#
#                 img = Image.fromarray(string_mat)
#                 img.save(os.path.join(dst_path, txt_file.replace('.txt', '.png')))
#             except Exception as e:
#                 print(traceback.format_exc())
#                 pass
#
#     file_list = os.listdir(file_path)
#     for asm in file_list:
#         with io.open(os.path.join(file_path, asm), 'r', encoding='ISO-8859-1') as f:
#             print('open %s...' % asm)
#             ASMFeatureExtractor(f.read(), dst_path, asm)
#
#     GenerateDllFuncImg(os.path.join(dst_path, 'DllFunc'), os.path.join(dst_path, 'DllFuncImg'))
#     GenerateStrImg(os.path.join(dst_path, 'string'), file_path, os.path.join(dst_path, 'stringImg'))
#
#
# def Generate_FastText_TrainSet(src_path, FastText_path, data_type='OPCODE'):
#     if not os.path.exists(FastText_path):
#         os.makedirs(FastText_path)
#     try:
#         # make all_data.txt file
#         all_data_element = open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % data_type), 'a')
#
#         file_list = os.listdir(src_path)
#         print('file count = %d' % len(file_list))
#         for txt_file in file_list:
#             md5_hash = txt_file
#             if md5_hash.find(".txt") != -1:
#                 md5_hash = md5_hash.replace(".txt", "")
#             if md5_hash.find("VirusShare_") != -1:
#                 md5_hash = md5_hash.replace("VirusShare_", "")
#
#             with open(os.path.join(src_path, txt_file), 'r') as f:
#                 lines = f.readlines()
#
#                 all_data_element.write(md5_hash + '##')
#                 for line in lines:
#                     elem_name = line
#                     if elem_name.find("?") != -1:
#                         elem_name = elem_name.replace("?", "")
#                     if elem_name.find(" ") != -1:
#                         elem_name = elem_name.replace(" ", "")
#                     if elem_name.find("\n") != -1:
#                         elem_name = elem_name.replace("\n", "")
#
#                     all_data_element.write(elem_name.strip() + ' ')
#                 del lines
#                 all_data_element.write('\n')
#
#         all_data_element.close()
#     except Exception as e:
#         print(traceback.format_exc())
#         pass
#
#
# def label_del(FastText_path, name='OPCODE'):
#     train_label = open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % name), 'r')
#     train_label_lines = train_label.readlines()
#     save = open(os.path.join(FastText_path, '%s_FastText_train.txt' % name), 'w')
#     for line in train_label_lines:
#         try:
#             contents = line.split('##')[1]
#             save.write(contents + '\n')
#         except Exception as e:
#             print(traceback.format_exc())
#             pass
#     train_label.close()
#     save.close()
#
#
# def train_FastText(FastText_path, name='OPCODE', total_exam=500):
#     models_path = os.path.join(FastText_path, 'models')
#     if not os.path.exists(models_path):
#         os.makedirs(models_path)
#
#     logging.basicConfig(format='%(asctime)s:%(levelname)s: %(message)s', level=logging.INFO)
#     sentences = word2vec.Text8Corpus(os.path.join(FastText_path, '%s_FastText_train.txt' % name))
#
#     print("\nStart ==> FastText 64 Vector Size train\n")
#     FT64_model = FastText(sg=0, hs=1, size=64, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
#     FT64_model.build_vocab(sentences)
#     FT64_model.train(sentences, total_examples=total_exam, epochs=100)
#     FT64_model.save(os.path.join(models_path, '%s_64size' % name))
#     print("\nFinish ==> FastText 64 Vector Size train\n")
#     del FT64_model
#
#     print("\nStart ==> FastText 128 Vector Size train\n")
#     FT128_model = FastText(sg=0, hs=1, size=128, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
#     FT128_model.build_vocab(sentences)
#     FT128_model.train(sentences, total_examples=total_exam, epochs=100)
#     FT128_model.save(os.path.join(models_path, '%s_128size' % name))
#     print("\nFinish ==> FastText 128 Vector Size train\n")
#     del FT128_model
#
#     print("\nStart ==> FastText 256 Vector Size train\n")
#     FT256_model = FastText(sg=0, hs=1, size=256, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
#     FT256_model.build_vocab(sentences)
#     FT256_model.train(sentences, total_examples=total_exam, epochs=100)
#     FT256_model.save(os.path.join(models_path, '%s_256size' % name))
#     print("\nFinish ==> FastText 256 Vector Size train\n")
#     del FT256_model
#
#     print("\nStart ==> FastText 512 Vector Size train\n")
#     FT512_model = FastText(sg=0, hs=1, size=512, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
#     FT512_model.build_vocab(sentences)
#     FT512_model.train(sentences, total_examples=total_exam, epochs=100)
#     FT512_model.save(os.path.join(models_path, '%s_512size' % name))
#     print("\nFinish ==> FastText 512 Vector Size train\n")
#     del FT512_model
#
#
# def GenerateFastTextImg(FastText_path, img_base_dir, name='', embedding_size=512):
#     FastText_file = os.path.join(FastText_path, 'models/%s_%ssize' % (name, embedding_size))
#     FastText_model = FastText.load(FastText_file)
#
#     words = []
#     for i in range(len(FastText_model.wv.vocab)):
#         words.append(FastText_model.wv.index2word[i])
#
#     embedding_matrix = np.zeros((len(words), embedding_size))
#     embedding_vector_dict = {}
#     for i in range(len(words)):
#         if words[i] in FastText_model.wv.vocab:
#             embedding_vector_list = FastText_model.wv[words[i]].tolist()
#             embedding_vector_dict[words[i]] = embedding_vector_list
#             embedding_vector = FastText_model.wv[words[i]]
#             embedding_matrix[i] = embedding_vector
#     max_value = embedding_matrix.max()
#     min_value = embedding_matrix.min()
#
#     for key in embedding_vector_dict:
#         value_list = embedding_vector_dict[key]
#         for cnt in range(len(value_list)):
#             embedding_vector_dict[key][cnt] = int(255 * ((value_list[cnt] - min_value) / (max_value - min_value)))
#
#     img_dst_path = os.path.join(img_base_dir, '%s' % embedding_size)
#     if not os.path.exists(img_dst_path):
#         os.makedirs(img_dst_path)
#     with open(os.path.join(FastText_path, '%s_FastText_train_labeled.txt' % name), 'r') as f:
#         lines = f.readlines()
#         for line in lines:
#             label, contents = line.split('##')
#             contents_list = contents.rstrip().split(' ')
#             height = len(contents_list)
#             mat = np.zeros((height, embedding_size), dtype=int)
#             for y in range(height):
#                 embedding_vector_list = embedding_vector_dict[contents_list[y]]
#                 x = 0
#                 for x_value in embedding_vector_list:
#                     mat[y][x] = x_value
#                     x += 1
#             img = Image.fromarray(mat)
#             img.save(os.path.join(img_dst_path, '%s.png' % label))

# def log(str):
#     global fpp
#     print(str)
#     fpp.write(str)
#     fpp.write("\n")
#
# def addr_handler(dbg):
#     global func_name
#     ret_addr = dbg.context.Eax
#     if ret_addr:
#         dict[ret_addr] = func_name
#         dbg.bp_set(ret_addr, handler=generic)
#     return DBG_CONTINUE
#
# def generic(dbg):
#     global func_name
#     eip = dbg.context.Eip
#     esp = dbg.context.Esp
#     paddr = dbg.read_process_memory(esp, 4)
#     addr = struct.unpack("L", paddr)[0]
#     addr = int(addr)
#     if addr < 70000000:
#         log("RETURN ADDRESS: 0x%.8x\tCALL: %s" % (addr, dict[eip]))
#     if dict[eip] == "KERNEL32!GetProcAddress" or dict[eip] == "GetProcAddress":
#         try:
#             esp = dbg.context.Esp
#             addr = esp + 0x8
#             size = 50
#             pstring = dbg.read_process_memory(addr, 4)
#             pstring = struct.unpack("L", pstring)[0]
#             pstring = int(pstring)
#             if pstring > 500:
#                 data = dbg.read_process_memory(pstring, size)
#                 func_name = dbg.get_ascii_string(data)
#             else:
#                 func_name = "Ordinal entry"
#             paddr = dbg.read_process_memory(esp, 4)
#             addr = struct.unpack("L", paddr)[0]
#             addr = int(addr)
#             dbg.bp_set(addr, handler=addr_handler)
#         except:
#             pass
#     return DBG_CONTINUE
#
# def entryhandler(dbg):
#     getaddr = dbg.func_resolve("kernel32.dll", "GetProcAddress")
#     dict[getaddr] = "kernel32!GetProcAddress"
#     dbg.bp_set(getaddr, handler=generic)
#     for entry in pe.DIRECTORY_ENTRY_IMPORT:
#         DllName = entry.dll
#         for imp in entry.imports:
#             api = imp.name
#             address = dbg.func_resolve(DllName, api)
#             if address:
#                 try:
#                     Dllname = DllName.split(".")[0]
#                     dll_func = Dllname + "!" + api
#                     dict[address] = dll_func
#                     dbg.bp_set(address, handler=generic)
#                 except:
#                     pass
#     return DBG_CONTINUE


def ExtractOpcode(src_path, dst_path):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    file_list = os.listdir(src_path)
    finish_list = os.listdir(dst_path)
    print("extract start!")
    file_cnt = 0
    for exe_file in file_list:
        try:
            check_file_name = exe_file.replace('.vir', '.txt')
            if check_file_name in finish_list:
                print("file = %s  =>  is Finish File... PASS" % check_file_name)
                pass
            else:
                file_cnt += 1
                print("%d  ||  extract opcode at %s ..." % (file_cnt, exe_file))
                # Address of Dataset to analysis
                current_file = os.path.join(src_path, exe_file)

                # PE file and file(bytes) open
                pe = pefile.PE(current_file)
                open_exe = open(current_file, 'rb')
                data = open_exe.read()
                for sec in pe.sections:
                    if '.text' in sec.Name:
                        raw_size = sec.SizeOfRawData

                EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

                # Start disassembly at the EP
                offset = EntryPoint
                Endpoint = offset + raw_size

                now_opcode = ''
                opcodelist = []
                opcode_len_limit = 600
                opcode_len_cnt = 0
                while offset < Endpoint:
                    # Get the first instruction
                    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                    if not i:
                        break

                    # Print a string representation if the instruction
                    opcodes = pydasm.get_mnemonic_string(i, pydasm.FORMAT_INTEL)
                    opcodes = opcodes.split(' ')[0]
                    if (now_opcode != opcodes) and (opcode_len_cnt < opcode_len_limit) and ('?' not in opcodes) and (('@' not in opcodes)) and (('!' not in opcodes)):
                        now_opcode = opcodes
                        opcodelist.append(now_opcode)
                        opcode_len_cnt += 1
                    if opcode_len_cnt == opcode_len_limit:
                        break
                    # Go to the next instruction
                    offset += int(i.length)

                # write opcode set
                try:
                    if opcodelist[0] or opcodelist[0] != '':
                        # Loop until the end of the .text section => OPCODE list extract
                        with open(os.path.join(dst_path, exe_file.replace('.vir', '.txt')), 'w') as f_opcode:
                            for op in opcodelist:
                                f_opcode.write(op + '\n')
                except Exception as e:
                    pass

        except Exception as e:
            print("Error! about : " + exe_file)
            with open(os.path.join(dst_path, exe_file.replace('.vir', '.txt')), 'a') as f_opcode:
                f_opcode.write('')
            print(traceback.format_exc())
            pass


def ExtractApiCalls(src_path, dst_path):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    with open('./DLL_LIST.txt', 'r') as f_dll_ALL:
        line = f_dll_ALL.readline()
        DLL_LIST = line.rstrip(' ').split(' ')
    with open('./API_LIST.txt', 'r') as f_api_ALL:
        line = f_api_ALL.readline()
        API_LIST = line.rstrip(' ').split(' ')

    file_list = os.listdir(src_path)
    finish_list = os.listdir(dst_path)
    print("extract start!")
    file_cnt, save_file_cnt = 0, 0
    for exe_file in file_list:
        try:
            check_file_name = exe_file.replace('.vir', '.txt')
            if check_file_name in finish_list:
                print("file = %s  =>  is Finish File... PASS" % check_file_name)
                pass
            else:
                file_cnt += 1
                print("%d  ||  extract API calls at %s ..." % (file_cnt, exe_file))
                # Address of Dataset to analysis
                current_file = os.path.join(src_path, exe_file)
                # PE file and file(bytes) open
                pe = pefile.PE(current_file)
                open_exe = open(current_file, 'rb')
                data = open_exe.read()
                for sec in pe.sections:
                    if '.text' in sec.Name:
                        raw_size = sec.SizeOfRawData

                EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

                # Start disassembly at the EP
                offset = EntryPoint
                Endpoint = offset + raw_size

                API_dict1, API_dict2 = {}, {}
                for item in pe.DIRECTORY_ENTRY_IMPORT:
                    DLL_data = str(item.dll).replace('.DLL', '.dll')
                    if DLL_data not in DLL_LIST:
                        pass
                    else:
                        for import_fn in item.imports:
                            try:
                                if import_fn.name not in API_LIST:
                                    pass
                                else:
                                    API_dict1['[%s]' % hex(import_fn.address)] = import_fn.name
                                    API_dict2[hex(import_fn.address)] = import_fn.name
                            except:
                                pass

                # Loop until the end of the .text section => OPCODE list extract
                now_api, this_api_name = '', ''
                apilist = []
                api_len_limit = 600
                api_len_cnt = 0
                while offset < Endpoint:
                    # Get the first instruction
                    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                    if not i:
                        break

                    try:
                        op_string1 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
                        op_string2 = pydasm.get_operand_string(i, 1, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
                        op_string3 = pydasm.get_operand_string(i, 2, pydasm.FORMAT_INTEL, offset + EntryPoint_va)

                        if API_dict1[op_string1] or API_dict2[op_string1]:
                            if '[' in op_string1:
                                this_api_name = API_dict1[op_string1]
                            else:
                                this_api_name = API_dict2[op_string1]
                        elif API_dict1[op_string2] or API_dict2[op_string2]:
                            if '[' in op_string2:
                                this_api_name = API_dict1[op_string2]
                            else:
                                this_api_name = API_dict2[op_string2]
                        elif API_dict1[op_string3] or API_dict2[op_string3]:
                            if '[' in op_string3:
                                this_api_name = API_dict1[op_string3]
                            else:
                                this_api_name = API_dict2[op_string3]

                        del op_string1, op_string2, op_string3

                    except Exception as e:
                        pass

                    if (now_api != this_api_name) and (api_len_cnt < api_len_limit):
                        now_api = this_api_name
                        apilist.append(now_api)
                        api_len_cnt += 1

                    if api_len_cnt == api_len_limit:
                        break

                    # Go to the next instruction
                    offset += int(i.length)

                # write API set
                if api_len_cnt > 50:
                    save_file_cnt += 1
                    with open(os.path.join(dst_path, exe_file.replace('.vir', '.txt')), 'w') as f_api:
                        for api in apilist:
                            f_api.write(api + '\n')

                del apilist, pe, open_exe, data, API_dict1, API_dict2

        except Exception as e:
            print("Error! about : " + exe_file)
            print(traceback.format_exc())
            pass


def ExtractDllApi(src_path, dst_path):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    with open('./DLL_LIST.csv', 'r') as f_dll:
        DLL_LIST = []
        lines = csv.reader(f_dll)
        for line in lines:
            DLL_LIST.append(line[0])
    with open('./API_LIST.csv', 'r') as f_api:
        API_LIST = []
        lines = csv.reader(f_api)
        for line in lines:
            API_LIST.append(line[0])

    file_list = os.listdir(src_path)
    file_cnt = 0
    print("extract start!")
    for exe_file in file_list:
        try:
            file_cnt += 1
            print("%d  ||  extract DLL-API at %s ..." % (file_cnt, exe_file))
            # Address of Dataset to analysis
            current_file = os.path.join(src_path, exe_file)
            # PE file and file(bytes) open
            pe = pefile.PE(current_file)

            # DLL and API list extract
            with open(os.path.join(dst_path, exe_file.replace('.vir', '.txt')), 'w') as f_DllApi:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    DLL_name = str(entry.dll).lower()
                    if DLL_name.find('.dll') == -1:
                        DLL_name += '.dll'
                    if DLL_name in DLL_LIST:
                        try:
                            f_DllApi.write('%s:' % DLL_name)
                            for API in entry.imports:
                                API_name = str(API.name).lower()
                                if API_name.find("?") != -1:
                                    API_name = API_name.replace('?', '')
                                if API_name.find("@") != -1:
                                    API_name = API_name.replace('@', '')
                                if API_name.find("$") != -1:
                                    API_name = API_name.replace('$', '')
                                if API_name == "none":
                                    API_name = API_name.replace('none', '')

                                if API_name in API_LIST:
                                    f_DllApi.write(' %s' % API_name)
                                else:
                                    pass
                            f_DllApi.write('\n')
                        except:
                            pass
                    else:
                        pass


        except Exception as e:
            print("Error! about : " + exe_file)
            print(traceback.format_exc())
            pass


# before edit at 221024
# def GenerateDllApiImg(src_path, dst_path):
#     with open('./DLL_LIST.txt', 'r') as f_dll_ALL:
#         line = f_dll_ALL.readline()
#         DLL_LIST = line.rstrip(' ').split(' ')
#     with open(os.path.join('./TotalSet', 'API_Calls_Frequencies.csv'), 'r') as f_api_ALL:
#         API_LIST = []
#         lines = csv.reader(f_api_ALL)
#         for line in lines:
#             if int(line[1]) >= 100:
#                 API_LIST.append(line[0])
#
#     if not os.path.exists(dst_path):
#         os.makedirs(dst_path)
#
#     file_list = os.listdir(src_path)
#     file_cnt = 0
#     print("Generate start!")
#     for exe_file in file_list:
#         try:
#             file_cnt += 1
#             print("%d  ||  Generate DLL-API Image at %s ..." % (file_cnt, exe_file))
#
#             DLL_API_matrix = np.zeros((len(DLL_LIST), len(API_LIST)), dtype=np.uint8)
#
#             # extract API at PEfile
#             current_file = os.path.join(src_path, exe_file)
#             # PE file and file(bytes) open
#             pe = pefile.PE(current_file)
#             open_exe = open(current_file, 'rb')
#             data = open_exe.read()
#             for sec in pe.sections:
#                 if '.text' in sec.Name:
#                     raw_size = sec.SizeOfRawData
#
#             EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
#             EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase
#
#             # Start disassembly at the EP
#             offset = EntryPoint
#             Endpoint = offset + raw_size
#
#             # Generate DLL-API dictionary
#             API_dict1, API_dict2 = {}, {}
#             for item in pe.DIRECTORY_ENTRY_IMPORT:
#                 DLL_data = str(item.dll).replace('.DLL', '.dll')
#                 if DLL_data not in DLL_LIST:
#                     pass
#                 else:
#                     for import_fn in item.imports:
#                         try:
#                             if import_fn.name not in API_LIST:
#                                 pass
#                             else:
#                                 API_dict1['[%s]' % hex(import_fn.address)] = [DLL_data, import_fn.name]
#                                 API_dict2[hex(import_fn.address)] = [DLL_data, import_fn.name]
#                         except:
#                             pass
#
#             apilist, dlllist = [], []
#             while offset < Endpoint:
#                 # Get the first instruction
#                 i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
#                 if not i:
#                     break
#
#                 try:
#                     op_string1 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
#                     op_string2 = pydasm.get_operand_string(i, 1, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
#                     op_string3 = pydasm.get_operand_string(i, 2, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
#
#                     if API_dict1[op_string1] or API_dict2[op_string1]:
#                         if '[' in op_string1:
#                             this_dll_name = API_dict1[op_string1][0]
#                             this_api_name = API_dict1[op_string1][1]
#                         else:
#                             this_dll_name = API_dict2[op_string1][0]
#                             this_api_name = API_dict2[op_string1][1]
#
#                     elif API_dict1[op_string2] or API_dict2[op_string2]:
#                         if '[' in op_string2:
#                             this_dll_name = API_dict1[op_string2][0]
#                             this_api_name = API_dict1[op_string2][1]
#                         else:
#                             this_dll_name = API_dict2[op_string2][0]
#                             this_api_name = API_dict2[op_string2][1]
#
#                     elif API_dict1[op_string3] or API_dict2[op_string3]:
#                         if '[' in op_string3:
#                             this_dll_name = API_dict1[op_string3][0]
#                             this_api_name = API_dict1[op_string3][1]
#                         else:
#                             this_dll_name = API_dict2[op_string3][0]
#                             this_api_name = API_dict2[op_string3][1]
#                     del op_string1, op_string2, op_string3
#
#                     dlllist.append(this_dll_name)
#                     apilist.append(this_api_name)
#
#                 except Exception as e:
#                     pass
#
#                 # Go to the next instruction
#                 offset += int(i.length)
#
#             for elem_cnt in range(len(apilist)):
#                 DLL_name = dlllist[elem_cnt].rstrip('\n')
#                 API_name = apilist[elem_cnt].rstrip('\n')
#                 y = DLL_LIST.index(DLL_name)
#                 x = API_LIST.index(API_name)
#                 if DLL_API_matrix[y][x] == 255:
#                     pass
#                 else:
#                     DLL_API_matrix[y][x] += 1
#             img = Image.fromarray(DLL_API_matrix, 'L')
#             img.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))
#             del DLL_API_matrix
#
#         except Exception as e:
#             img = Image.fromarray(DLL_API_matrix, 'L')
#             img.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))
#             del DLL_API_matrix
#             print(traceback.format_exc())
#             pass


# after edit at 221024
def GenerateDllApiImg(src_path, dst_path):
    DLL_LIST, API_LIST = [], []
    with open('./DLLAPI_matrix.csv', 'r') as f:
        rdr = csv.reader(f)
        for line in rdr:
            DLL_LIST.append(line[0])
            API_LIST.append(line[1:])
    width_max = 0
    TOTAL_API_LIST = []
    for list_tmp in API_LIST:
        if len(list_tmp) > width_max:
            width_max = len(list_tmp)
        for api in list_tmp:
            if api not in TOTAL_API_LIST:
                TOTAL_API_LIST.append(api)
    height_max = len(DLL_LIST)

    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    file_list = os.listdir(src_path)
    file_cnt = 0
    print("Generate start!")
    for exe_file in file_list:
        try:
            DLL_API_matrix = np.zeros((height_max, width_max), dtype=np.uint8)

            # extract API at PEfile
            current_file = os.path.join(src_path, exe_file)
            # PE file and file(bytes) open
            pe = pefile.PE(current_file)
            open_exe = open(current_file, 'rb')
            data = open_exe.read()
            for sec in pe.sections:
                if '.text' in sec.Name:
                    raw_size = sec.SizeOfRawData

            EntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            EntryPoint_va = EntryPoint + pe.OPTIONAL_HEADER.ImageBase

            # Start disassembly at the EP
            offset = EntryPoint
            Endpoint = offset + raw_size

            # Generate DLL-API dictionary
            API_dict1, API_dict2 = {}, {}
            for item in pe.DIRECTORY_ENTRY_IMPORT:
                DLL_data = str(item.dll).lower()
                if DLL_data in DLL_LIST:
                    dll_index = DLL_LIST.index(DLL_data)
                    for import_fn in item.imports:
                        API_data = import_fn.name
                        try:
                            API_data = API_data.lower()
                            if API_data in TOTAL_API_LIST:
                                API_dict1['[%s]' % hex(import_fn.address)] = [DLL_data, API_data]
                                API_dict2[hex(import_fn.address)] = [DLL_data, API_data]
                        except:
                            pass

            apilist, dlllist = [], []
            while offset < Endpoint:
                # Get the first instruction
                i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                if not i:
                    break
                try:
                    op_string1 = pydasm.get_operand_string(i, 0, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
                    op_string2 = pydasm.get_operand_string(i, 1, pydasm.FORMAT_INTEL, offset + EntryPoint_va)
                    op_string3 = pydasm.get_operand_string(i, 2, pydasm.FORMAT_INTEL, offset + EntryPoint_va)

                    if API_dict1[op_string1] or API_dict2[op_string1]:
                        if '[' in op_string1:
                            this_dll_name = API_dict1[op_string1][0]
                            this_api_name = API_dict1[op_string1][1]
                        else:
                            this_dll_name = API_dict2[op_string1][0]
                            this_api_name = API_dict2[op_string1][1]

                    elif API_dict1[op_string2] or API_dict2[op_string2]:
                        if '[' in op_string2:
                            this_dll_name = API_dict1[op_string2][0]
                            this_api_name = API_dict1[op_string2][1]
                        else:
                            this_dll_name = API_dict2[op_string2][0]
                            this_api_name = API_dict2[op_string2][1]

                    elif API_dict1[op_string3] or API_dict2[op_string3]:
                        if '[' in op_string3:
                            this_dll_name = API_dict1[op_string3][0]
                            this_api_name = API_dict1[op_string3][1]
                        else:
                            this_dll_name = API_dict2[op_string3][0]
                            this_api_name = API_dict2[op_string3][1]
                    del op_string1, op_string2, op_string3

                    dlllist.append(this_dll_name)
                    apilist.append(this_api_name)
                except Exception as e:
                    pass
                # Go to the next instruction
                offset += int(i.length)

            for elem_cnt in range(len(apilist)):
                DLL_name = dlllist[elem_cnt]
                API_name = apilist[elem_cnt]
                y = DLL_LIST.index(DLL_name)
                x = API_LIST[y].index(API_name)
                if DLL_API_matrix[y][x] == 255:
                    pass
                else:
                    DLL_API_matrix[y][x] += 1

            img = Image.fromarray(DLL_API_matrix, 'L')
            img.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))
            file_cnt += 1
            print("%d  ||  Generate DLL-API Image at %s ..." % (file_cnt, exe_file))
            del DLL_API_matrix

        except Exception as e:
            img = Image.fromarray(DLL_API_matrix, 'L')
            img.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))
            del DLL_API_matrix
            print(traceback.format_exc())
            pass


def ExtractString_GenImg(src_path, dst_path):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    file_list = os.listdir(src_path)
    finish_list = os.listdir(dst_path)
    print("extract start!")
    file_cnt, max_height = 0, 0
    for exe_file in file_list:
        try:
            check_file_name = exe_file.replace('.vir', '.txt')
            if check_file_name in finish_list:
                print("file = %s  =>  is Finish File... PASS" % check_file_name)
                pass
            else:
                file_cnt += 1
                print("%d  ||  extract Strings and Generate String image at %s ..." % (file_cnt, exe_file))
                # Address of Dataset to analysis
                current_file = os.path.join(src_path, exe_file)
                # PE file and file(bytes) open
                pe = pefile.PE(current_file)

                strings = []
                try:
                    rt_string_idx = [
                        entry.id for entry in
                        pe.DIRECTORY_ENTRY_RESOURCE.entries
                    ].index(pefile.RESOURCE_TYPE['RT_STRING'])
                except:
                    pass

                rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
                for entry in rt_string_directory.directory.entries:
                    data_rva = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                    offset = 0
                    while True:
                        if offset >= size:
                            break
                        ustr_length = pe.get_word_from_data(data[offset:offset + 2], 0)
                        offset += 2

                        if ustr_length == 0:
                            continue

                        ustr = pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                        offset += ustr_length * 2
                        strings.append(ustr)

                string_list = []
                for str_data in strings:
                    string_tmp = ''
                    for i in str_data:
                        string_tmp += str(ord(i)) + ' '
                    string_list.append(string_tmp)

                # generate image of string
                try:
                    file_size = os.path.getsize(current_file)
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
                            try:
                                string_mat[y][x] = mat_list[y][x]
                            except:
                                pass
                    img = Image.fromarray(string_mat, 'L')
                    img.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))

                except Exception as e:
                    print(traceback.format_exc())
                    pass

        except Exception as e:
            print("Error! about : " + exe_file)
            # print(traceback.format_exc())
            pass


def GenerateByteImg(src_path, dst_path):
    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    file_list = os.listdir(src_path)
    print("extract start!")
    file_cnt = 0
    for exe_file in file_list:
        try:
            file_cnt += 1
            print("%d  ||  Generate Byte Image at %s ..." % (file_cnt, exe_file))
            current_file = os.path.join(src_path, exe_file)
            byte_data_list = []
            with open(current_file, "rb") as f:
                try:
                    byte = f.read(1).encode("hex")
                    byte_data_list.append(int(byte, 16))
                    while byte:
                        try:
                            byte = f.read(1).encode("hex")
                            byte_data_list.append(int(byte, 16))
                        except:
                            pass
                except:
                    pass
            file_size = round(os.path.getsize(current_file) / 1024)
            if file_size < 10:
                image_width = 32
            elif (file_size >= 10) and (file_size < 30):
                image_width = 64
            elif (file_size >= 30) and (file_size < 60):
                image_width = 128
            elif (file_size >= 60) and (file_size < 100):
                image_width = 256
            elif (file_size >= 100) and (file_size < 200):
                image_width = 384
            elif (file_size >= 200) and (file_size < 500):
                image_width = 512
            elif (file_size >= 500) and (file_size < 1000):
                image_width = 784
            else:
                image_width = 1024

            image_height = int(len(byte_data_list) / image_width) + 1
            byte_data_array = np.array(byte_data_list, dtype=np.uint8)
            image = np.zeros((image_height, image_width), dtype=np.uint8)

            exist_data_idx = 0
            for height in range(0, image_height):
                for width in range(0, image_width):
                    if exist_data_idx >= len(byte_data_list):
                        image[height, width] = 0
                    else:
                        image[height, width] = byte_data_array[exist_data_idx]
                    exist_data_idx += 1

            byte_image = Image.fromarray(image, 'L')
            byte_image.save(os.path.join(dst_path, exe_file.replace('.vir', '.jpg')))

        except Exception as e:
            print("Error! about : " + exe_file)
            print(traceback.format_exc())
            pass


if __name__ == '__main__':
    # run_opcode_extractor(Dataset_path='./dataset/RANSOMWARE/VirusShare_Locker_20150505/', txt_path='./dataset/RANSOMWARE/RANSOM_OPCODE/')
    # run_opcode_extractor(Dataset_path='./dataset/RANSOMWARE/VirusShare_CryptoRansom_20160715/', txt_path='./dataset/RANSOMWARE/RANSOM_OPCODE/')

    DATASET_SRC_PATH = './KISAset/trainSet/trainSet'
    MALWARE_SRC_PATH = './KISAset/malware/'
    # BENIGN_ORIGIN_SRC_PATH = './KISAset/benign_dataset/benign_else/'
    # BENIGN_SRC_PATH = './KISAset/benign/'
    BENIGN_SRC_PATH = './KISAset/benign/'
    LABEL_FILE = './KISAset/labels/trainSet.csv'

    STATIC_FEATURE_PATH = './KISAset/BenignFeatures/'
    OPCODE_FEATURE_PATH = os.path.join(STATIC_FEATURE_PATH, 'Opcode')
    DLL_API_FEATURE_PATH = os.path.join(STATIC_FEATURE_PATH, 'DllApi')
    DLL_API_IMAGE_PATH = os.path.join(STATIC_FEATURE_PATH, 'DllApiImg')
    API_FEATURE_PATH = os.path.join(STATIC_FEATURE_PATH, 'Api')
    STRING_FEATURE_PATH = os.path.join(STATIC_FEATURE_PATH, 'StringImg')
    BYTE_IMG_DST_PATH = os.path.join(STATIC_FEATURE_PATH, 'ByteImg')

    # 1-1. malware and benign classfication using label file in KISA dataset
    # KISA_LABEL_Classifier(DATASET_SRC_PATH, MALWARE_SRC_PATH, BENIGN_SRC_PATH, LABEL_FILE)

    # 1-2. Move benign dataset just 1208 data
    # CopyBenignDataset(BENIGN_ORIGIN_SRC_PATH, STATIC_FEATURE_PATH, BENIGN_SRC_PATH, data_number=1208)

    # 2. extract opcode at PEfile
    # ExtractOpcode(BENIGN_SRC_PATH, OPCODE_FEATURE_PATH)

    # 3. extract API calls at PEfile
    # ExtractApiCalls(BENIGN_SRC_PATH, API_FEATURE_PATH)

    # 4. extract DLL-API at PEfile
    # ExtractDllApi(BENIGN_SRC_PATH, DLL_API_FEATURE_PATH)
    GenerateDllApiImg(BENIGN_SRC_PATH, DLL_API_IMAGE_PATH)

    # 4. extract String at PEfile
    # ExtractString_GenImg(BENIGN_SRC_PATH, STRING_FEATURE_PATH)

    # 5. Transform PE file to Byte file and IMAGE
    # GenerateByteImg(BENIGN_SRC_PATH, BYTE_IMG_DST_PATH)
