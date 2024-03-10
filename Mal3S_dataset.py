import os
import csv
import logging
import traceback
import numpy as np
from PIL import Image

from gensim.models import word2vec
from gensim.models.fasttext import FastText


class Mal3SDataset:
    def __init__(
            self, dataset_base_dir, bytes_file_base_dir,
            image_base_dir, bytes_images_dir, opcode_images_dir, api_images_dir, dll_api_images_dir, string_images_dir,
    ):
        self.DATASET_BASE_DIR = dataset_base_dir
        self.BYTES_FILE_DIR = bytes_file_base_dir

        self.IMG_BASE_DIR = image_base_dir
        self.BYTES_IMG_PATH = bytes_images_dir
        self.OPCODE_IMG_PATH = opcode_images_dir
        self.API_IMG_PATH = api_images_dir
        self.DLL_API_IMG_PATH = dll_api_images_dir
        self.STRING_IMG_PATH = string_images_dir

        self.file_size_range = [0, 10, 30, 60, 100, 200, 500, 1000]
        self.image_width_size = [32, 64, 128, 256, 384, 512, 768, 1024]

    def format_hex_line(self, address, data):
        """Format a line with the address and hexadecimal data."""
        hex_data = ' '.join(f'{byte:02X}' for byte in data)
        return f'{address:08X} {hex_data}'

    def extract_pe_to_hex(self):
        """Extracts the PE file to a formatted hex view."""
        dataset_list = os.listdir(self.DATASET_BASE_DIR)
        for data in dataset_list:
            with open(os.path.join(self.DATASET_BASE_DIR, data), 'rb') as pe_file, open(os.path.join(self.BYTES_FILE_DIR, data), 'w') as output_file:
                # PE 파일을 바이트 단위로 읽기
                byte_data = pe_file.read()

                offset = 0
                for byte in byte_data:
                    # 16 바이트(16진수)마다 줄바꿈하여 주소 표시
                    if offset % 16 == 0:
                        output_file.write(f'\n{offset:08X} ')

                    # 바이트를 16진수 형태로 변환하여 기록
                    output_file.write(f'{byte:02X} ')
                    offset += 1

    def bytes_to_grayscale_image(self):
        '''
        // Bytes file to grayscale image code //

        ===================================
         Bytes file size별 image width 설정
        ===================================
        file size → round(file_size(bytes) / 1024) # 단위 변경을 위해 div1024 [B → KB]

        file size: < 10KB → image width: 32
        10KB <= file size < 30KB → image width: 64
        30KB <= file size < 60KB → image width: 128
        60KB <= file size < 100KB → image width: 256
        100KB <= file size < 200KB → image width: 384
        200KB <= file size < 500KB → image width: 512
        500KB <= file size < 1000KB → image width: 784
        1000KB < file size → image width: 1024
        '''

        print_success_file_count = 0
        byte_file_list = os.listdir(self.BYTES_FILE_DIR)    # Dataset folder 내 bytes file 목록 가져오기

        for byte_file in byte_file_list:
            try:
                file_size = round(os.path.getsize(os.path.join(self.BYTES_FILE_DIR, byte_file)) / 1024)

                byte_data_list = []
                with open(os.path.join(self.BYTES_FILE_DIR, byte_file), 'r') as file:  # with open → close 필요 X
                    byte_data_lines = file.readlines()

                for byte_data_line in byte_data_lines:
                    byte_data_line = byte_data_line.strip()
                    space_split_data = byte_data_line.split(' ')
                    '''
                    space_split_data 구조
                    [ID, hexData_1, hexData_2, ... , hexData_N + \n(없는 경우도 존재함)]
    
                    활용하지 않는 ID 값을 제외하기 위해 idx:1 부터 데이터 추출
                    '''
                    for idx in range(1, len(space_split_data)):
                        if idx == len(space_split_data) - 1:  # 리스트 내 마지막 인덱스에 존재하는 \n을 제거하기 위해 마지막 인덱스 값 확인
                            if len(space_split_data[idx]) == 3:  # 개행문자 있는 경우, \n 제거 || 없는 경우는 pass!
                                space_split_data[idx] = space_split_data[idx][:2]

                        '''
                        ?? 의미 : 알수없는 원인으로 인해 깨지거나 추출되지 않은 데이터
                        따라서, 본 연구에서는 ??를 0으로 변경
                        '''
                        if space_split_data[idx] == '??':
                            space_split_data[idx] = '00'  # 형변환을 한번에 수행하기 위해서 string형인 0으로 변경

                        byte_data_list.append(int(space_split_data[idx], 16))  # string형 16진수를 int형 10진수로 변경

                # File size별로 image width 설정
                image_width = self.image_width_size[0]
                for idx in range(0, len(self.file_size_range)):
                    if idx == len(self.file_size_range) - 1:
                        if self.file_size_range[idx] <= file_size:
                            image_width = self.image_width_size[idx]

                        if self.file_size_range[idx] <= file_size < self.file_size_range[idx]:
                            image_width = self.image_width_size[idx]

                image_height = int(len(byte_data_list) / image_width) + 1  # image width에 따라 image height 설정
                byte_data_array = np.array(byte_data_list, dtype=np.uint8)
                image = np.zeros((image_height, image_width), dtype=np.uint8)  # image frame 생성

                exist_data_idx = 0
                for height in range(0, image_height):
                    for width in range(0, image_width):
                        if exist_data_idx >= len(byte_data_list):  # Image 내 pixel 개수 > byte data 개수일 경우, 남은 부분은 0으로 변경
                            image[height, width] = 0
                        else:
                            image[height, width] = byte_data_array[exist_data_idx]  # Data 순서에 따라 image 생성
                        exist_data_idx += 1

                # mat max > 0인 경우에만 img 생성
                if np.max(image) > 0:
                    byte_image = Image.fromarray(image, 'L')  # Grayscale image 생성
                    byte_image.save(os.path.join(self.BYTES_IMG_PATH, '%s.jpg' % os.path.splitext(byte_file)[0]))

                print_success_file_count += 1
                print('Successful in imaging bytes file to grayscale image ----> [%d/%d (%.4f%%)]'
                      % (print_success_file_count, len(byte_file_list),
                         (print_success_file_count / len(byte_file_list) * 100)))
            except Exception as e:
                print(str(e))
                pass

    def generate_fasttext_trainset(self, target_path, model_save_path, format='opcode'):
        if not os.path.exists(model_save_path):
            os.makedirs(model_save_path)

        try:
            # make all_data.txt file
            all_data_element = open(os.path.join(model_save_path, '%s_FastText_train_labeled.txt' % format), 'a')

            file_list = os.listdir(target_path)
            print('file count = %d' % len(file_list))
            for txt_file in file_list:
                filename = os.path.splitext(txt_file)[0]
                if filename.find("VirusShare_") != -1:
                    filename = filename.replace("VirusShare_", "")

                with open(os.path.join(target_path, txt_file), 'r') as f:
                    lines = f.readlines()

                    all_data_element.write(filename + '##')
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

    def delete_label(self, model_save_path, format='opcode'):
        train_label = open(os.path.join(model_save_path, '%s_FastText_train_labeled.txt' % format), 'r')
        train_label_lines = train_label.readlines()
        save = open(os.path.join(model_save_path, '%s_FastText_train.txt' % format), 'w')
        for line in train_label_lines:
            try:
                contents = line.split('##')[1]
                save.write(contents + '\n')
            except Exception as e:
                print(traceback.format_exc())
                pass
        train_label.close()
        save.close()

    # build vocab.txt file
    def build_vocab(self, model, vocab_dir):
        words = []
        for word in model.wv.key_to_index:
            words.append(word)

        # Add <pad> to word_vocab
        words = ['<PAD>'] + list(words)

        open(vocab_dir, mode='w', encoding='utf-8', errors='ignore').write('\n'.join(words) + '\n')

    def train_fasttext(self, model_save_path, format='opcode', embedding_size=512):
        models_path = os.path.join(model_save_path, 'models')
        if not os.path.exists(models_path):
            os.makedirs(models_path)

        logging.basicConfig(format='%(asctime)s:%(levelname)s: %(message)s', level=logging.INFO)
        sentences = word2vec.Text8Corpus(os.path.join(model_save_path, '%s_FastText_train.txt' % format))

        print("\nStart ==> FastText %s Vector Size train\n" % embedding_size)
        FT_model = FastText(sg=0, hs=1, vector_size=embedding_size, window=5, min_count=1, workers=4, negative=5, min_n=2, max_n=6)
        FT_model.build_vocab(sentences)
        total_examples = sum(1 for _ in sentences)
        FT_model.train(sentences, total_examples=total_examples, epochs=100)
        FT_model.save(os.path.join(models_path, '%s_%ssize' % (format, str(embedding_size))))
        print("\nFinish ==> FastText %s Vector Size train\n" % embedding_size)

        # Save vocab to txt
        self.build_vocab(FT_model, os.path.join(models_path, '%s_%ssize_vocabulary.txt' % (format, str(embedding_size))))

        del FT_model

    def fasttext_to_grayscale_image(self, model_save_path, format='', embedding_size=512):
        FastText_file = os.path.join(model_save_path, 'models/%s_%ssize' % (format, embedding_size))
        FastText_model = FastText.load(FastText_file)

        words = []
        for word in FastText_model.wv.key_to_index.keys():
            words.append(word)

        embedding_matrix = np.zeros((len(words), embedding_size))
        embedding_vector_dict = {}
        for i in range(len(words)):
            if words[i] in FastText_model.wv.key_to_index:
                embedding_vector_list = FastText_model.wv[words[i]].tolist()
                embedding_vector_dict[words[i]] = embedding_vector_list    # word에 대한 embedding vector를 dictionary에 저장
                embedding_vector = FastText_model.wv[words[i]]
                embedding_matrix[i] = embedding_vector
        max_value = embedding_matrix.max()
        min_value = embedding_matrix.min()
        
        for key in embedding_vector_dict:
            value_list = embedding_vector_dict[key]
            for cnt in range(len(value_list)):
                embedding_vector_dict[key][cnt] = int(255 * ((value_list[cnt] - min_value) / (max_value - min_value)))

        img_dst_path = os.path.join(self.IMG_BASE_DIR, '%s/%s' % (format, embedding_size))
        if not os.path.exists(img_dst_path):
            os.makedirs(img_dst_path)

        print_success_file_count = 0
        with open(os.path.join(model_save_path, '%s_FastText_train_labeled.txt' % format), 'r') as f:
            lines = f.readlines()
            for line in lines:
                try:
                    label, contents = line.split('##')
                    contents_list = contents.rstrip().split(' ')
                    height = len(contents_list)
                    mat = np.zeros((height, embedding_size), dtype=np.uint8)
                    for y in range(height):
                        try:
                            embedding_vector_list = embedding_vector_dict[contents_list[y]]
                            x = 0
                            for x_value in embedding_vector_list:
                                mat[y][x] = x_value
                                x += 1
                        except Exception as e:
                            print(str(e))
                            pass

                    # mat max > 0인 경우에만 img 생성
                    if np.max(mat) > 0:
                        img = Image.fromarray(mat, 'L')
                        img.save(os.path.join(img_dst_path, '%s.jpg' % label))

                    print_success_file_count += 1
                    print('%d => %s' % (print_success_file_count, label))

                except Exception as e:
                    print(str(e))
                    pass

    def dll_api_frequencies_to_grayscale_image(self, feature_base_dir, dll_api_feature_dir):
        dll_idx_list, api_idx_list = [], []
        with open(os.path.join(feature_base_dir, 'DLL_API_Frequencies_matrix.csv'), 'r') as f:
            rdr = csv.reader(f)
            for line in rdr:
                dll_idx_list.append(line[0])
                api_idx_list.append(line[1:])

        width_max = 0
        total_api_list = []
        for list_tmp in api_idx_list:
            if len(list_tmp) > width_max:
                width_max = len(list_tmp)
            for api in list_tmp:
                if api not in total_api_list:
                    total_api_list.append(api)
        height_max = len(dll_idx_list)

        dll_api_feature_list = os.listdir(dll_api_feature_dir)

        print_success_file_count = 0
        for dll_api_feature in dll_api_feature_list:
            DLL_API_matrix = np.zeros((height_max, width_max), dtype=np.uint8)
            try:
                with open(os.path.join(dll_api_feature_dir, dll_api_feature), 'r') as f_txt:
                    dll_api_dict = {}
                    this_file_API_list = []
                    lines = f_txt.readlines()
                    for line in lines:
                        dll_name, API_names = line.split(':')
                        API_names = API_names.lstrip(' ')
                        API_names = API_names.rstrip('\n')
                        if API_names:
                            dll_api_dict[dll_name] = API_names.split(' ')
                            for this_api in dll_api_dict[dll_name]:
                                if this_api not in this_file_API_list:
                                    this_file_API_list.append(this_api)
                        else:
                            dll_api_dict[dll_name] = []

                for key, value_list in dll_api_dict.items():
                    try:
                        y = dll_idx_list.index(key)
                        if value_list:
                            for value in value_list:
                                if value in this_file_API_list:
                                    x = api_idx_list[y].index(value)
                                    if DLL_API_matrix[y][x] == 255:
                                        pass
                                    else:
                                        DLL_API_matrix[y][x] += 1
                    except Exception as e:
                        pass

                # DLL_API_matrix.max > 0인 경우에만 img 생성
                if np.max(DLL_API_matrix) > 0:
                    img = Image.fromarray(DLL_API_matrix, 'L')
                    img.save(os.path.join(self.DLL_API_IMG_PATH, '%s.jpg' % os.path.splitext(dll_api_feature)[0]))
                    print_success_file_count += 1
                    print("%d => Generate DLL-API Image at %s ..." % (print_success_file_count, dll_api_feature))

                del DLL_API_matrix

            except Exception as e:
                del DLL_API_matrix
                print(traceback.format_exc())

        self.dll_api_frequencies_to_normalized_grayscale_image(width=width_max, height=height_max)

    def dll_api_frequencies_to_normalized_grayscale_image(self, width, height):
        img_filename_list = os.listdir(self.DLL_API_IMG_PATH)
        image_count = len(img_filename_list)    # 전체 이미지 개수

        # Initialize the matrix
        matrix = np.zeros((image_count, width * height), dtype=np.uint8)

        for i, image_file in enumerate(img_filename_list):
            try:
                with Image.open(os.path.join(self.DLL_API_IMG_PATH, image_file)) as img:
                    # Assuming images are grayscale
                    matrix[i, :] = np.array(img).flatten()
            except IOError:
                print(f"Error opening {image_file}. Skipping.")
                continue

        # Normalize the matrix
        min_vals = matrix.min(axis=1, keepdims=True)
        max_vals = matrix.max(axis=1, keepdims=True)
        normalized_matrix = np.divide(
            255 * (matrix - min_vals), max_vals - min_vals,
            where=(max_vals - min_vals) != 0, out=np.zeros_like(matrix, dtype=float)
        )
        normalized_matrix[np.isnan(normalized_matrix)] = 0

        for i in range(image_count):
            try:
                # Reshape the row back into the original image dimensions
                image_array = normalized_matrix[i].reshape(height, width)

                # Convert to an image and save
                image = Image.fromarray(image_array.astype(np.uint8), 'L')
                image.save(os.path.join(self.DLL_API_IMG_PATH, 'norm_%s' % img_filename_list[i]))
            except IOError:
                print(f"Error saving {img_filename_list[i]}. Skipping.")
                continue

    def string_to_grayscale_image(self, string_feature_dir):
        print("string_to_grayscale_image start!")

        file_list = os.listdir(self.DATASET_BASE_DIR)
        file_cnt, max_height = 0, 0
        print_success_file_count = 0
        for exe_file in file_list:
            try:
                filename = os.path.splitext(exe_file)[0]

                # Address of Dataset to analysis
                current_file = os.path.join(self.DATASET_BASE_DIR, exe_file)

                # generate image of string
                file_size = os.path.getsize(current_file)
                file_size = file_size / 1024
                width = 32
                if (file_size >= 10) and (file_size < 30):
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

                with open(os.path.join(string_feature_dir, '%s.txt' % filename), 'r') as f_txt:
                    lines = f_txt.readlines()

                    mat_list, row_list = [], []
                    for line in lines:
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

                    # string_mat의 max > 0인 경우에만 img 생성
                    if np.max(string_mat) > 0:
                        img = Image.fromarray(string_mat, 'L')
                        img.save(os.path.join(self.STRING_IMG_PATH, '%s.jpg' % os.path.splitext(exe_file)[0]))
                        print_success_file_count += 1
                        print("%d => Generate DLL-API Image at %s ..." % (print_success_file_count, exe_file))


            except Exception as e:
                print("Error! about : " + exe_file)
                print(traceback.format_exc())
                pass