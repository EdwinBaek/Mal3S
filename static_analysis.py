"""
    2023.11.10 백승연 : static analysis code 정리
    기초 static analysis data 추출 코드
"""
import os
import re
import csv

from capstone import *
import pefile


class PEfileStaticAnalyzer:
    def __init__(
            self, dataset_base_dir, log_base_dir, saved_base_dir, feature_base_dir,
            opcode_feature_dir, api_feature_dir, dll_api_feature_dir, string_feature_dir
    ):
        """
        Extract features(bytes, opcode, API calls, DLLs-API calls frequencies, Strings) at PE file

        :param dataset_base_dir : PE file이 저장된 base dircectory
        :param log_base_dir : log 파일 저장 base directory
        :param saved_base_dir : data 저장 base dircectory
        """
        # Base directory
        self.DATASET_BASE_DIR = dataset_base_dir
        self.LOG_BASE_DIR = log_base_dir
        self.SAVED_BASE_DIR = saved_base_dir

        # Extracted feature 저장 path
        self.FEATURE_BASE_DIR = feature_base_dir
        self.OPCODE_FEATURE_DIR = opcode_feature_dir
        self.API_FEATURE_DIR = api_feature_dir
        self.DLL_API_FEATURE_DIR = dll_api_feature_dir
        self.STRING_FEATURE_DIR = string_feature_dir

        self.global_api_cnt_dict = {}

        # File path
        self.EXTRACTED_FILE_LOG = os.path.join(log_base_dir, 'static_analyzed_files.txt')
        if not os.path.isfile(self.EXTRACTED_FILE_LOG):
            f = open(self.EXTRACTED_FILE_LOG, 'w')
            f.close()

    def extract_features(self):
        # feature extract가 완료된 filename list 확인
        extracted_filename_list = []
        log_file = open(self.EXTRACTED_FILE_LOG, 'r')
        lines = log_file.readlines()
        for line in lines:
            extracted_filename_list.append(line.replace('\n', ''))

        # extract features (opcode, API calls, DLLs, Strings)
        dataset_file_list = os.listdir(self.DATASET_BASE_DIR)
        for filename in dataset_file_list:
            try:
                self.filename = os.path.splitext(filename)[0]
                # 이미 opcode extract가 끝난 파일의 경우 pass
                if self.filename in extracted_filename_list:
                    print("%s  is already extraced..." % filename)
                    pass
                # Extract static features
                else:
                    print("extract features at  %s" % filename)
                    current_file = os.path.join(self.DATASET_BASE_DIR, filename)

                    self.pe = pefile.PE(current_file)  # open PE file as pefile format
                    open_exe = open(current_file, 'rb')  # open PE file as bytes format
                    self.data = open_exe.read()

                    raw_size = self.pe.sections[0].SizeOfRawData
                    entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    entry_point_va = entry_point + self.pe.OPTIONAL_HEADER.ImageBase

                    # Start disassembly at the EP
                    self.offset = entry_point
                    self.end_point = self.offset + raw_size

                    self.extract_opcode_feature()
                    self.extract_dll_api_frequency_feature()
                    self.extract_string_feature()

                    with open(self.EXTRACTED_FILE_LOG, mode='a', newline='', encoding='utf-8') as f:
                        f.write(self.filename + '\n')

                    self.pe.close()

                    del self.filename, self.pe, self.data, self.offset, self.end_point

            except Exception as e:
                print(str(e))
                pass
        self.generate_dll_api_frequency_matrix()

    # 영어가 아닌 다른 글자 삭제
    def cleaning_chars(self, target_str):
        regex_pattern = '[^a-zA-Z]'                            # Regular expression to match non-ASCII characters
        cleaned_str = re.sub(regex_pattern, '', target_str)    # Replace non-ASCII characters with an empty string
        return cleaned_str

    def extract_opcode_feature(self):
        # Extracting Opcodes
        opcode_list = []
        now_opcode = ''    # 중복 opcode 확인을 위한 변수
        opcode_cnt = 0
        if hasattr(self.pe, 'sections'):
            for section in self.pe.sections:
                if section.Characteristics & 0x20000000:    # Check if executable
                    md = Cs(CS_ARCH_X86, CS_MODE_32)        # Initialize disassembler for x86 32-bit
                    for i in md.disasm(section.get_data(), 0x1000):
                        opcode_str = i.mnemonic
                        opcode_str = self.cleaning_chars(opcode_str)
                        if opcode_str != now_opcode:
                            opcode_list.append(opcode_str)
                            now_opcode = opcode_str
                            opcode_cnt += 1

                            if opcode_cnt == 600:
                                break

                if opcode_cnt == 600:
                    break

        # write opcode list
        with open(os.path.join(self.OPCODE_FEATURE_DIR, '%s.txt' % self.filename), 'w') as f_opcode:
            try:
                for op in opcode_list:
                    f_opcode.write(op + '\n')
            except Exception as e:
                pass

        del opcode_list, now_opcode

    def extract_dll_api_frequency_feature(self):
        api_calls_list, dlls_list = [], []
        frequency_dict = {}    # DLLs & API Calls frequency에 대한 dictionary (key is DLL, value is list of API calls)
        api_cnt = 0
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                # DLLs 추출
                try:
                    dll_str = entry.dll.decode('utf-8').lower()
                    dll_str = self.cleaning_chars(dll_str)
                    dll_str = dll_str.replace('dll', '.dll')
                    if dll_str.find('dll') == -1:
                        dll_str += '.dll'
                    if dll_str not in dlls_list:
                        dlls_list.append(dll_str)

                    # DLL-API matrix를 위한 frequency matrix 생성 => 해당 DLL에 대한 key 생성
                    if dll_str not in frequency_dict:
                        frequency_dict[dll_str] = []

                    # API calls 추출
                    for imp in entry.imports:
                        if imp.name is not None:
                            api_calls_str = imp.name.decode('utf-8').lower()
                            api_calls_str = self.cleaning_chars(api_calls_str)
                            if api_cnt < 600:
                                api_calls_list.append(api_calls_str)
                                api_cnt += 1
                            self.global_api_cnt_dict[api_calls_str] = self.global_api_cnt_dict.get(api_calls_str, 0) + 1

                            # DLL-API matrix를 위한 frequency matrix 생성 => 해당 DLL에 대한 API calls 저장
                            # if api_calls_str not in frequency_dict[dll_str]:
                            frequency_dict[dll_str].append(api_calls_str)

                except Exception as e:
                    pass

        # write DLL and API
        with open(os.path.join(self.DLL_API_FEATURE_DIR, '%s.txt' % self.filename), 'w') as f_dll:
            for key, value in frequency_dict.items():
                try:
                    f_dll.write('%s:' % key)
                    for i in range(len(value)):
                        f_dll.write(' %s' % value[i])
                    f_dll.write('\n')
                except Exception as e:
                    pass

        # write API calls
        with open(os.path.join(self.API_FEATURE_DIR, '%s.txt' % self.filename), 'w') as f_api:
            try:
                for api in api_calls_list:
                    f_api.write(api + '\n')
            except Exception as e:
                pass

    def generate_dll_api_frequency_matrix(self):
        # write DLL-API frequency matrix to CSV
        sorted_dict = sorted(self.global_api_cnt_dict.items(), key=lambda item: item[1], reverse=True)
        with open(os.path.join(self.FEATURE_BASE_DIR, 'DLL_API_Frequencies.csv'), 'w', newline='', encoding='utf-8') as f:
            wr = csv.writer(f)
            for key, value in sorted_dict:
                wr.writerow([key, value])

        del self.global_api_cnt_dict, sorted_dict

        new_API_LIST = []
        with open(os.path.join(self.FEATURE_BASE_DIR, 'DLL_API_Frequencies.csv'), 'r') as f_api:
            lines = csv.reader(f_api)
            for line in lines:
                if int(line[1]) >= 100:
                    new_API_LIST.append(line[0])

        print('\nremove min count API count : len(new_API_LIST) = %d' % len(new_API_LIST))
        dll_api_freuqencies_features = os.listdir(self.DLL_API_FEATURE_DIR)
        DLL_API_dict = {}
        for txt_file in dll_api_freuqencies_features:
            with open(os.path.join(self.DLL_API_FEATURE_DIR, txt_file), 'r') as f:
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
        with open(os.path.join(self.FEATURE_BASE_DIR, 'DLL_API_Frequencies_matrix.csv'), 'w', newline='', encoding='utf-8') as f:
            wr = csv.writer(f)
            for key, item in DLL_API_dict.items():
                if len(item) > max_cnt:
                    max_cnt = len(item)
                item.insert(0, key)
                wr.writerow(item)
                dll_cnt += 1
        print('max_cnt = %d' % max_cnt)
        print('dll_cnt = %d' % dll_cnt)

    def extract_string_feature(self):
        strings = re.findall(b'[ -~]{4,}', self.pe.get_memory_mapped_image())
        string_list = [s.decode('utf-8') for s in strings]

        with open(os.path.join(self.STRING_FEATURE_DIR, '%s.txt' % self.filename), 'w') as f_str:
            try:
                for str_ in string_list:
                    for char_ in str_:
                        tmp = int(ord(char_))
                        f_str.write('%s ' % tmp)
                    f_str.write('\n')
            except Exception as e:
                pass