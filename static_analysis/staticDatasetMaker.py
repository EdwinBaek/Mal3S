import os
import re
import traceback


def Generate_OPSet(FastText_path='', op_file_path=''):
    # make directory of String image destination
    if not os.path.exists(FastText_path):
        os.makedirs(FastText_path)
    try:
        # make all_data.txt file
        all_data_element = open(os.path.join(FastText_path, 'OPCODE_FastText_train_labeled.txt'), 'a', encoding='utf-8')

        op_file_list = os.listdir(op_file_path)
        for txt_file in op_file_list:
            md5_hash = txt_file
            if md5_hash.find(".txt") != -1:
                md5_hash = md5_hash.replace(".txt", "")
            if md5_hash.find("VirusShare_") != -1:
                md5_hash = md5_hash.replace("VirusShare_", "")

            with open(os.path.join(op_file_path, txt_file), 'r') as op_file:
                lines = op_file.readlines()

                all_data_element.write(md5_hash + '##')
                for opline in lines:
                    opcode = opline
                    if opcode.find("?") != -1:
                        opcode = opcode.replace("?", "")
                    if opcode.find(" ") != -1:
                        opcode = opcode.replace(" ", "")
                    if opcode.find("\n") != -1:
                        opcode = opcode.replace("\n", "")

                    all_data_element.write(opcode.strip() + ' ')
                del lines
                all_data_element.write('\n')

        all_data_element.close()

    except Exception as e:
        print(traceback.format_exc())
        pass

def label_del(name='OPCODE'):
    train_label = open('./ransomware_dataset/FastText/%s_FastText_train_labeled.txt' % name, 'r')
    train_label_lines = train_label.readlines()
    save = open('./ransomware_dataset/FastText/%s_FastText_train.txt' % name, 'w')
    for line in train_label_lines:
        try:
            contents = line.split('##')[1]
            save.write(contents + '\n')
        except Exception as e:
            print(traceback.format_exc())
            pass
    train_label.close()
    save.close()




if __name__ == '__main__':
    Generate_OPSet()
    label_del()
    train_FastText()