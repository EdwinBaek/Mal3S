"""
static_analysis
Mal3S_dataset 사용
"""
import os
import csv
import sys
import shutil
import pefile

from static_analysis import PEfileStaticAnalyzer
from Mal3S_dataset import Mal3SDataset


class Mal3SDatasetProcessor:
    def __init__(self, dataset_name='KISA', dataset_base_dir='', save_file_dir=''):
        print('%s dataset...' % dataset_name)
        self.DATASET_BASE_DIR = dataset_base_dir
        self.LOG_BASE_DIR = './%s/log' % dataset_name
        self.SAVED_BASE_DIR = save_file_dir
        self.BYTES_FILE_BASE_DIR = os.path.join(self.SAVED_BASE_DIR, 'bytes')

        self.FEATURE_BASE_DIR = os.path.join(self.SAVED_BASE_DIR, 'features')
        self.OPCODE_FEATURE_DIR = os.path.join(self.FEATURE_BASE_DIR, 'opcode')
        self.API_FEATURE_DIR = os.path.join(self.FEATURE_BASE_DIR, 'api')
        self.DLL_API_FEATURE_DIR = os.path.join(self.FEATURE_BASE_DIR, 'dll_api')
        self.STRING_FEATURE_DIR = os.path.join(self.FEATURE_BASE_DIR, 'string')

        self.IMG_BASE_DIR = os.path.join(self.SAVED_BASE_DIR, 'images')    # 외부 저장장치(큰 용량)로 변경할 것
        self.BYTES_IMG_DIR = os.path.join(self.IMG_BASE_DIR, 'bytes')
        self.OPCODE_IMG_DIR = os.path.join(self.IMG_BASE_DIR, 'opcode')
        self.API_IMG_DIR = os.path.join(self.IMG_BASE_DIR, 'api')
        self.DLL_API_IMG_DIR = os.path.join(self.IMG_BASE_DIR, 'dll_api')
        self.STRING_IMG_DIR = os.path.join(self.IMG_BASE_DIR, 'string')

        self.FASTTEXT_MODEL_BASE_DIR = os.path.join(self.SAVED_BASE_DIR, 'fasttext')
        self.embedding_size = 64

        self.init_dir()

    def init_dir(self):
        # directory init 생성
        if not os.path.exists(self.LOG_BASE_DIR):
            os.makedirs(self.LOG_BASE_DIR)
        if not os.path.exists(self.SAVED_BASE_DIR):
            os.makedirs(self.SAVED_BASE_DIR)
        if not os.path.exists(self.BYTES_FILE_BASE_DIR):
            os.makedirs(self.BYTES_FILE_BASE_DIR)

        if not os.path.exists(self.OPCODE_FEATURE_DIR):
            os.makedirs(self.OPCODE_FEATURE_DIR)
        if not os.path.exists(self.API_FEATURE_DIR):
            os.makedirs(self.API_FEATURE_DIR)
        if not os.path.exists(self.DLL_API_FEATURE_DIR):
            os.makedirs(self.DLL_API_FEATURE_DIR)
        if not os.path.exists(self.STRING_FEATURE_DIR):
            os.makedirs(self.STRING_FEATURE_DIR)

        if not os.path.exists(self.BYTES_IMG_DIR):
            os.makedirs(self.BYTES_IMG_DIR)
        if not os.path.exists(self.OPCODE_IMG_DIR):
            os.makedirs(self.OPCODE_IMG_DIR)
        if not os.path.exists(self.API_IMG_DIR):
            os.makedirs(self.API_IMG_DIR)
        if not os.path.exists(self.DLL_API_IMG_DIR):
            os.makedirs(self.DLL_API_IMG_DIR)
        if not os.path.exists(self.STRING_IMG_DIR):
            os.makedirs(self.STRING_IMG_DIR)

        if not os.path.exists(self.FASTTEXT_MODEL_BASE_DIR):
            os.makedirs(self.FASTTEXT_MODEL_BASE_DIR)

    def preprocess_dataset(self):
        self.extract_static_analysis_features()
        self.generate_Mal3S_dataset()

    def extract_static_analysis_features(self):
        analyzer = PEfileStaticAnalyzer(
            dataset_base_dir=self.DATASET_BASE_DIR,
            log_base_dir=self.LOG_BASE_DIR,
            saved_base_dir=self.SAVED_BASE_DIR,
            feature_base_dir=self.FEATURE_BASE_DIR,
            opcode_feature_dir=self.OPCODE_FEATURE_DIR,
            api_feature_dir=self.API_FEATURE_DIR,
            dll_api_feature_dir=self.DLL_API_FEATURE_DIR,
            string_feature_dir=self.STRING_FEATURE_DIR
        )
        analyzer.extract_features()

    def generate_Mal3S_dataset(self):
        dataset = Mal3SDataset(
            dataset_base_dir=self.DATASET_BASE_DIR,
            bytes_file_base_dir=self.BYTES_FILE_BASE_DIR,
            image_base_dir=self.IMG_BASE_DIR,
            bytes_images_dir=self.BYTES_IMG_DIR,
            opcode_images_dir=self.OPCODE_IMG_DIR,
            api_images_dir=self.API_IMG_DIR,
            dll_api_images_dir=self.DLL_API_IMG_DIR,
            string_images_dir=self.STRING_IMG_DIR
        )

        # bytes to image set
        dataset.extract_pe_to_hex()         # PE to bytes
        dataset.bytes_to_grayscale_image()  # generate bytes image dataset

        # opcode to image set
        # train FastText model of opcode
        dataset.generate_fasttext_trainset(
            target_path=self.OPCODE_FEATURE_DIR,
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='opcode'
        )
        dataset.delete_label(model_save_path=self.FASTTEXT_MODEL_BASE_DIR, format='opcode')
        dataset.train_fasttext(
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='opcode',
            embedding_size=self.embedding_size
        )
        # generate opcode image dataset
        dataset.fasttext_to_grayscale_image(
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='opcode',
            embedding_size=self.embedding_size
        )

        # API calls to image set
        # train FastText model of API calls
        dataset.generate_fasttext_trainset(
            target_path=self.API_FEATURE_DIR,
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='api'
        )
        dataset.delete_label(model_save_path=self.FASTTEXT_MODEL_BASE_DIR, format='api')
        dataset.train_fasttext(
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='api',
            embedding_size=self.embedding_size
        )
        # generate API calls image dataset
        dataset.fasttext_to_grayscale_image(
            model_save_path=self.FASTTEXT_MODEL_BASE_DIR,
            format='api',
            embedding_size=self.embedding_size
        )

        # DLL-API calls frequency to image set
        # generate DLL-API calls frequency image dataset
        dataset.dll_api_frequencies_to_grayscale_image(self.FEATURE_BASE_DIR, self.DLL_API_FEATURE_DIR)

        # string to image set
        # generate string image dataset
        dataset.string_to_grayscale_image(string_feature_dir=self.STRING_FEATURE_DIR)


class DatasetClassifier:
    def __init__(self, dataset_base_dir='', dataset_dst_dir='', label_files=[], new_label_file='', malware_cnt=0, benign_cnt=0):
        self.DATASET_BASE_DIR = dataset_base_dir        # filtering 전 dataset directory
        self.DATASET_DST_DIR = dataset_dst_dir          # filtering된 dataset directory

        self.label_files = label_files
        self.new_label_file = new_label_file
        self.malware_cnt = malware_cnt
        self.benign_cnt = benign_cnt

        if not os.path.exists(self.DATASET_DST_DIR):
            os.makedirs(self.DATASET_DST_DIR)

    def file_size_sorting(self, file_dir, reverse_flag=True):
        # 폴더 내의 모든 파일과 디렉터리 목록을 가져옴
        file_list = os.listdir(file_dir)

        # 파일 크기에 따라 정렬 (reverse_flag가 True인 경우 파일 크기가 큰 순서)
        file_list.sort(key=lambda x: os.path.getsize(os.path.join(file_dir, x)), reverse=reverse_flag)

        # # 정렬된 파일 목록 출력
        # for file in file_list:
        #     size = os.path.getsize(os.path.join(file_dir, file))
        #     print(f"파일 이름: {file}, 크기: {size} 바이트")

        return file_list

    def is_pe_file(self, file_path):
        pe_flag = False
        try:
            with open(file_path, 'rb') as f:
                sign = f.read(2)
                if sign == b'MZ':
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), 'little')
                    f.seek(pe_offset)
                    pe_sign = f.read(4)
                    if pe_sign == b'PE\0\0':
                        pe_flag = True

            if pe_flag:
                pe_test = pefile.PE(file_path)    # open PE file as pefile format
                if pe_test:
                    pe_test.close()
                    del pe_test
                    return True
            return False

        except Exception as e:
            print(str(e))
            return False

    def KISA_data_classifier(self):
        """
            용량이 큰 순서대로 malware & benign을 분류하고,
            new label csv file을 작성함
        """
        init_mal_cnt, init_ben_cnt = 0, 0

        # label files로부터 dataset list 생성
        label_info_dict = {}
        for label_csv_path in self.label_files:
            with open(label_csv_path, mode='r', encoding='utf-8') as f:
                rdr = csv.reader(f)
                for line in rdr:
                    filename = line[0]
                    label = line[1]
                    label_info_dict[filename] = label

        file_list = self.file_size_sorting(file_dir=self.DATASET_BASE_DIR)
        for filename in file_list:
            try:
                # benign
                if label_info_dict[filename] == '0':
                    file_path = os.path.join(self.DATASET_BASE_DIR, filename)

                    # 해당 파일이 PE format && 최대 benign count를 넘기지 않을 경우
                    if (self.is_pe_file(file_path=file_path)) and (init_ben_cnt < self.benign_cnt):
                        shutil.move(file_path, os.path.join(self.DATASET_DST_DIR, filename))

                        # Write new label csv
                        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
                            writer = csv.writer(new_label_csv)
                            writer.writerow([filename, label_info_dict[filename]])

                        init_ben_cnt += 1

                # malware
                elif label_info_dict[filename] == '1':
                    file_path = os.path.join(self.DATASET_BASE_DIR, filename)

                    # 해당 파일이 PE format && 최대 malware count를 넘기지 않을 경우
                    if (self.is_pe_file(file_path=file_path)) and (init_mal_cnt < self.malware_cnt):
                        shutil.move(file_path, os.path.join(self.DATASET_DST_DIR, filename))

                        # Write new label csv
                        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
                            writer = csv.writer(new_label_csv)
                            writer.writerow([filename, label_info_dict[filename]])

                        init_mal_cnt += 1

            except Exception as e:
                print(str(e))
                pass

    def KISA_data_classifier_minimize(self):
        """
            malware는 용량이 큰 순서대로 분류하고,
            benign은 용량이 작은 순서대로 분류하여 new label csv file을 작성함
        """
        init_mal_cnt, init_ben_cnt = 0, 0

        # label files로부터 dataset list 생성
        label_info_dict = {}
        for label_csv_path in self.label_files:
            with open(label_csv_path, mode='r', encoding='utf-8') as f:
                rdr = csv.reader(f)
                for line in rdr:
                    filename = line[0]
                    label = line[1]
                    label_info_dict[filename] = label

        # malware는 용량이 큰 순서로 추출
        malware_file_list = self.file_size_sorting(file_dir=self.DATASET_BASE_DIR)
        for filename in malware_file_list:
            try:
                if label_info_dict[filename] == '1':
                    file_path = os.path.join(self.DATASET_BASE_DIR, filename)

                    # 해당 파일이 PE format && 최대 malware count를 넘기지 않을 경우
                    if (self.is_pe_file(file_path=file_path)) and (init_mal_cnt < self.malware_cnt):
                        shutil.copy2(file_path, os.path.join(self.DATASET_DST_DIR, filename))

                        # Write new label csv
                        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
                            writer = csv.writer(new_label_csv)
                            writer.writerow([filename, label_info_dict[filename]])

                        init_mal_cnt += 1

            except Exception as e:
                print(str(e))
                pass

            if init_mal_cnt >= self.malware_cnt:
                break

        # benign는 용량이 작은 순서로 추출
        benign_file_list = self.file_size_sorting(file_dir=self.DATASET_BASE_DIR, reverse_flag=False)
        for filename in benign_file_list:
            try:
                if label_info_dict[filename] == '0':
                    file_path = os.path.join(self.DATASET_BASE_DIR, filename)

                    # 해당 파일이 PE format && 최대 malware count를 넘기지 않을 경우
                    if (self.is_pe_file(file_path=file_path)) and (init_ben_cnt < self.benign_cnt):
                        shutil.copy2(file_path, os.path.join(self.DATASET_DST_DIR, filename))

                        # Write new label csv
                        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
                            writer = csv.writer(new_label_csv)
                            writer.writerow([filename, label_info_dict[filename]])

                        init_ben_cnt += 1

            except Exception as e:
                print(str(e))
                pass

            if init_ben_cnt >= self.benign_cnt:
                break

    def VirusShare_data_classifier(self, malware_dataset_dir, benign_dataset_dir):
        init_mal_cnt, init_ben_cnt = 0, 0
        fail_cnt = 0

        # DATASET_BASE_DIR의 malware의 format 확인하고, PE일 경우 새로운 label file에 작성함
        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
            # 파일 용량이 큰 malware부터 new_label_file에 저장
            malware_list = self.file_size_sorting(file_dir=malware_dataset_dir)
            for filename in malware_list:
                try:
                    file_path = os.path.join(malware_dataset_dir, filename)
                    if (self.is_pe_file(file_path=file_path)) and (init_mal_cnt < self.malware_cnt):
                        shutil.move(os.path.join(malware_dataset_dir, filename),
                                    os.path.join(self.DATASET_DST_DIR, filename))

                        writer = csv.writer(new_label_csv)
                        writer.writerow([filename, '1'])

                        init_mal_cnt += 1
                        print('classified PE file (malware) = %s' % init_mal_cnt)
                    else:
                        fail_cnt += 1
                        print('Fail count of PE file (malware) = %s' % fail_cnt)

                except Exception as e:
                    print(str(e))
                    pass

        # label_files에서 bengin만 추출함
        # label files로부터 dataset list 생성
        benign_label_info_dict = {}
        for label_csv_path in self.label_files:
            with open(label_csv_path, mode='r', encoding='utf-8') as f:
                rdr = csv.reader(f)
                for line in rdr:
                    filename = line[0]
                    label = line[1]

                    # benign
                    if label == '0':
                        benign_label_info_dict[filename] = label

        benign_list = self.file_size_sorting(file_dir=benign_dataset_dir)
        for filename in benign_list:
            try:
                # benign
                if benign_label_info_dict[filename] == '0':
                    file_path = os.path.join(benign_dataset_dir, filename)
                    if (self.is_pe_file(file_path=file_path)) and (init_ben_cnt < self.benign_cnt):
                        shutil.copy2(os.path.join(benign_dataset_dir, filename),
                                     os.path.join(self.DATASET_DST_DIR, filename))

                        # Write new label csv
                        with open(self.new_label_file, mode='a', newline='', encoding='utf-8') as new_label_csv:
                            writer = csv.writer(new_label_csv)
                            writer.writerow([filename, benign_label_info_dict[filename]])

            except Exception as e:
                print(str(e))
                pass


if __name__ == '__main__':
    EXTERNAL_HDD_DIR = 'E:\Mal3S_review'

    KISA_DATASET_BASE_DIR = os.path.join(EXTERNAL_HDD_DIR, 'KISA_origin_dataset')
    KISA_REVIEW_DATASET_DIR = os.path.join(EXTERNAL_HDD_DIR, 'KISA_review_dataset')
    KISA_LABELS_DIR = os.path.join(EXTERNAL_HDD_DIR, 'KISA_labels')
    KISA_LABEL_CSV_FILES = [
        os.path.join(KISA_LABELS_DIR, 'trainSet.csv'), os.path.join(KISA_LABELS_DIR, 'preSet.csv'),
        os.path.join(KISA_LABELS_DIR, 'finalSet1.csv'), os.path.join(KISA_LABELS_DIR, 'finalSet2.csv')
    ]
    KISA_REVIEW_LABELS_DIR = os.path.join(KISA_LABELS_DIR, 'KISA_reviewSet.csv')
    KISA_SAVE_DIR = os.path.join(EXTERNAL_HDD_DIR, 'KISA_save')

    VS_DATASET_BASE_DIR = os.path.join(EXTERNAL_HDD_DIR, 'VirusShare_origin_dataset')
    VS_REVIEW_DATASET_DIR = os.path.join(EXTERNAL_HDD_DIR, 'VirusShare_review_dataset')
    VS_LABELS_DIR = os.path.join(EXTERNAL_HDD_DIR, 'VirusShare_labels')
    VS_LABEL_CSV_FILES = [os.path.join(VS_LABELS_DIR, 'KISA_reviewSet.csv')]
    VS_REVIEW_LABELS_DIR = os.path.join(VS_LABELS_DIR, 'VirusShare_reviewSet.csv')
    VS_SAVE_DIR = os.path.join(EXTERNAL_HDD_DIR, 'VirusShare_save')

    # KISA review dataset 분류
    kisa_classifier = DatasetClassifier(
        dataset_base_dir=KISA_DATASET_BASE_DIR, dataset_dst_dir=KISA_REVIEW_DATASET_DIR,
        label_files=KISA_LABEL_CSV_FILES, new_label_file=KISA_REVIEW_LABELS_DIR, malware_cnt=5000, benign_cnt=5000
    )
    kisa_classifier.KISA_data_classifier()

    # # VirusShare review dataset 분류
    # vs_classifier = DatasetClassifier(
    #     dataset_base_dir=VS_DATASET_BASE_DIR, dataset_dst_dir=VS_REVIEW_DATASET_DIR,
    #     label_files=VS_LABEL_CSV_FILES, new_label_file=VS_REVIEW_LABELS_DIR, malware_cnt=5000, benign_cnt=5000
    # )
    # vs_classifier.VirusShare_data_classifier(malware_dataset_dir=VS_DATASET_BASE_DIR, benign_dataset_dir=KISA_REVIEW_DATASET_DIR)

    # # Mal3S - KISA review dataset(Image) 생성
    # kisa_dataset_preprocessor = Mal3SDatasetProcessor(
    #     dataset_name='KISA', dataset_base_dir=KISA_REVIEW_DATASET_DIR, save_file_dir=KISA_SAVE_DIR
    # )
    # kisa_dataset_preprocessor.preprocess_dataset()
    #
    # # Mal3S - VirusShare review dataset(Image) 생성
    # kisa_dataset_preprocessor = Mal3SDatasetProcessor(
    #     dataset_name='VirusShare', dataset_base_dir=VS_REVIEW_DATASET_DIR, save_file_dir=VS_SAVE_DIR
    # )
    # kisa_dataset_preprocessor.preprocess_dataset()



