import csv
import math
import numpy as np
import time
import pandas as pd
from PIL import Image
import warnings
import torch
import torch.optim as optim
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torchsummary import summary
from torchvision import transforms
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from torch.autograd import Variable

warnings.filterwarnings("ignore")
GPU_NUM = 0  # Enter the desired GPU number
device = torch.device(f'cuda:{GPU_NUM}' if torch.cuda.is_available() else 'cpu')
print(torch.cuda.get_device_name(device))
torch.cuda.set_device(device)  # change allocation of current GPU
print('Available devices ', torch.cuda.device_count())
print('Current cuda device ', torch.cuda.current_device())

fastText_size = '64'

def get_Data_Info(path):
    read_File = open(path, 'r', encoding='utf-8')
    read_Data = csv.reader(read_File)
    data_List = []

    for data in read_Data:
        data_List.append(data)
    read_File.close()

    return data_List

class MalD3S_Dataset(Dataset):
    def __init__(self, mode, transform=None):
        self.transform = transform
        train_Data_Info = get_Data_Info('./Dataset/train.csv')
        valid_Data_Info = get_Data_Info('./Dataset/valid.csv')
        test_Data_Info = get_Data_Info('./Dataset/test.csv')

        if mode == 'train':
            self.train_Label = []
            self.train_Image = []
            self.images = []
            self.labels = []

            # cnt = 0
            for data_Info in train_Data_Info:
                self.train_Image.append(data_Info[0])
                self.train_Label.append(data_Info[1])
                # cnt += 1
                # if cnt == 80:
                #     break

            # self.byte_image = ['./Dataset/IMAGE/Byte_IMG/%s' % i for i in self.train_Image]
            # self.opcode_image = ['./Dataset/IMAGE/opcode_IMG/'+fastText_size+'/%s' % i for i in self.train_Image]
            # self.apicall_image = ['./Dataset/IMAGE/API_IMG/'+fastText_size+'/%s' % i for i in self.train_Image]
            self.string_image = ['./Dataset/IMAGE/string_IMG/%s' % i for i in self.train_Image]
            # self.dllapi_image = ['./Dataset/IMAGE/DllApi_IMG/%s' % i for i in self.train_Image]

            for idx in range(len(self.string_image)):
                # self.images.append(self.byte_image[idx])
                # self.images.append(self.opcode_image[idx])
                # self.images.append(self.apicall_image[idx])
                self.images.append(self.string_image[idx])
                # self.images.append(self.dllapi_image[idx])

            self.int_labels = list(map(int, self.train_Label))
            for label in self.int_labels:
                for iter in range(1):
                    self.labels.append(label)

        elif mode == 'valid':
            self.valid_Label = []
            self.valid_Image = []
            self.images = []
            self.labels = []

            # cnt = 0
            for data_Info in valid_Data_Info:
                self.valid_Image.append(data_Info[0])
                self.valid_Label.append(data_Info[1])
                # cnt += 1
                # if cnt == 10:
                #     break

            # self.byte_image = ['./Dataset/IMAGE/Byte_IMG/%s' % i for i in self.valid_Image]
            # self.opcode_image = ['./Dataset/IMAGE/opcode_IMG/'+fastText_size+'/%s' % i for i in self.valid_Image]
            # self.apicall_image = ['./Dataset/IMAGE/API_IMG/'+fastText_size+'/%s' % i for i in self.valid_Image]
            self.string_image = ['./Dataset/IMAGE/string_IMG/%s' % i for i in self.valid_Image]
            # self.dllapi_image = ['./Dataset/IMAGE/DllApi_IMG/%s' % i for i in self.valid_Image]

            for idx in range(len(self.string_image)):
                # self.images.append(self.byte_image[idx])
                # self.images.append(self.opcode_image[idx])
                # self.images.append(self.apicall_image[idx])
                self.images.append(self.string_image[idx])
                # self.images.append(self.dllapi_image[idx])

            self.int_labels = list(map(int, self.valid_Label))
            for label in self.int_labels:
                for iter in range(1):
                    self.labels.append(label)

        elif mode == 'test':
            self.test_Label = []
            self.test_Image = []
            self.images = []
            self.labels = []

            # cnt = 0
            for data_Info in test_Data_Info:
                self.test_Image.append(data_Info[0])
                self.test_Label.append(data_Info[1])
                # cnt += 1
                # if cnt == 10:
                #     break

            # self.byte_image = ['./Dataset/IMAGE/Byte_IMG/%s' % i for i in self.test_Image]
            # self.opcode_image = ['./Dataset/IMAGE/opcode_IMG/'+fastText_size+'/%s' % i for i in self.test_Image]
            # self.apicall_image = ['./Dataset/IMAGE/API_IMG/'+fastText_size+'/%s' % i for i in self.test_Image]
            self.string_image = ['./Dataset/IMAGE/string_IMG/%s' % i for i in self.test_Image]
            # self.dllapi_image = ['./Dataset/IMAGE/DllApi_IMG/%s' % i for i in self.test_Image]

            for idx in range(len(self.string_image)):
                # self.images.append(self.byte_image[idx])
                # self.images.append(self.opcode_image[idx])
                # self.images.append(self.apicall_image[idx])
                self.images.append(self.string_image[idx])
                # self.images.append(self.dllapi_image[idx])

            self.int_labels = list(map(int, self.test_Label))
            for label in self.int_labels:
                for iter in range(1):
                    self.labels.append(label)

    def __getitem__(self, index):
        image = self.images[index]
        label = self.labels[index]
        if self.transform is not None:
            image = self.transform(Image.open(image))

        return image, label

    def __len__(self):
        return len(self.labels)


class EarlyStopping:
    """Early stops the training if validation loss doesn't improve after a given patience."""
    def __init__(self, patience=7, verbose=False, hyperparameter=[], delta=0, path='checkpoint.pt', trace_func=print):
        """
        Args:
            patience (int): How long to wait after last time validation loss improved.
                            Default: 7
            verbose (bool): If True, prints a message for each validation loss improvement.
                            Default: False
            delta (float): Minimum change in the monitored quantity to qualify as an improvement.
                            Default: 0
            path (str): Path for the checkpoint to be saved to.
                            Default: 'checkpoint.pt'
            trace_func (function): trace print function.
                            Default: print
        """
        self.patience = patience
        self.verbose = verbose
        self.counter = 0
        self.best_score = None
        self.early_stop = False
        self.val_loss_min = np.Inf
        self.delta = delta
        self.path = path
        self.trace_func = trace_func
        self.hyperparameter = hyperparameter

    def __call__(self, val_loss, model1):
        score = -val_loss

        if self.best_score is None:
            self.best_score = score
            self.save_checkpoint(val_loss, model1)

        elif score < self.best_score + self.delta:
            self.counter += 1
            self.trace_func(f'\t\t\t\t\tEarlyStopping counter: {self.counter} out of {self.patience}')
            if self.counter >= self.patience:
                self.early_stop = True
        else:
            self.best_score = score
            self.save_checkpoint(val_loss, model1)
            self.counter = 0

    def save_checkpoint(self, val_loss, model1):
        '''Saves model when validation loss decrease.'''
        if self.verbose:
            self.trace_func(f'Validation loss decreased ({self.val_loss_min:.6f} --> {val_loss:.6f}).   Saving models ...')
        torch.save(model1.state_dict(), './Checkpoint/Single_String_ft-%s_hc-%s_oc-%s_hp-%s_op-%s_loss-%s_checkpoint.pt' % (fastText_size, self.hyperparameter[0], self.hyperparameter[1], self.hyperparameter[2], self.hyperparameter[3], self.hyperparameter[4]))
        self.val_loss_min = val_loss

def hidden_pooling(prev_conv, prev_conv_size, hidden_pool_size):
    for i in range(len(hidden_pool_size)):
        h, w = prev_conv_size
        h_window = math.ceil(h / hidden_pool_size[i])
        w_window = math.ceil(w / hidden_pool_size[i])
        h_stride = math.floor(h / hidden_pool_size[i])
        w_stride = math.floor(w / hidden_pool_size[i])

        max_pool = nn.MaxPool2d(kernel_size=(h_window, w_window), stride=(h_stride, w_stride))
        x = max_pool(prev_conv)
    return x

def spatial_pyramid_pooling(prev_conv, num_sample, prev_conv_size, out_pool_size):
    """
    prev_conv: 이전 conv layer의 output tensor
    num_sample: 이미지의 batch 수 => N
    prev_conv_size: 이전 conv layer의 output tensor의 width와 height이다.
    out_pool_size: a int vector of expected output size of max pooling layer, [1,2,4] 라는 배열을 넣는다
    :return: a tensor vector (1xn) is the concentration of multi-level pooling
    """
    for i in range(len(out_pool_size)):
        h, w = prev_conv_size
        h_window = math.ceil(h / out_pool_size[i])
        w_window = math.ceil(w / out_pool_size[i])
        h_stride = math.floor(h / out_pool_size[i])
        w_stride = math.floor(w / out_pool_size[i])

        max_pool = nn.MaxPool2d(kernel_size=(h_window, w_window), stride=(h_stride, w_stride))
        x = max_pool(prev_conv)
        if i == 0:
            spp = x.view(num_sample, -1)
        else:
            spp = torch.cat((spp, x.view(num_sample, -1)), 1)

    return spp

class single_feature_conv(nn.Module):
    def __init__(self, in_channel, hidden_channel, out_channel, output_pooling_size):
        super(single_feature_conv, self).__init__()

        self.output_pooling_size = output_pooling_size
        self.byte_conv_1 = nn.Conv2d(in_channel, hidden_channel//2, kernel_size=5, stride=1, padding=(512, 512))
        self.byte_pool_1 = nn.MaxPool2d(kernel_size=3, stride=2)

        self.byte_conv_2 = nn.Conv2d(hidden_channel//2, hidden_channel, kernel_size=5, stride=3)
        self.byte_pool_2 = nn.MaxPool2d(kernel_size=3, stride=2)

        self.byte_conv_3 = nn.Conv2d(hidden_channel, out_channel, kernel_size=3, stride=1)

    def forward(self, byte):
        byte_out = F.relu(self.byte_conv_1(byte))
        # print('single_byte_out conv1 shape >>> ', byte_out.shape, '\n')

        byte_out = self.byte_pool_1(byte_out)
        # print('single_byte_out pool1 shape >>> ', byte_out.shape, '\n')

        byte_out = F.relu(self.byte_conv_2(byte_out))
        # print('single_byte_out conv2 shape >>> ', byte_out.shape, '\n')

        byte_out = self.byte_pool_2(byte_out)
        # print('single_byte_out pool2 shape >>> ', byte_out.shape, '\n')

        byte_out = self.byte_conv_3(byte_out)
        # print('single_byte_out conv3 shape >>> ', byte_out.shape, '\n')

        out = spatial_pyramid_pooling(prev_conv=byte_out,
                                      num_sample=byte_out.size(0),
                                      prev_conv_size=[int(byte_out.size(2)), int(byte_out.size(3))],
                                      out_pool_size=self.output_pooling_size)

        # print('single feature conv_out shape >>> ', out.shape, '\n')
        return out

class Mal3S(nn.Module):
    def __init__(self, in_channel, hidden_channel, out_channel, output_pooling_size, num_class):
        super(Mal3S, self).__init__()
        self.single_feature_conv_layer = single_feature_conv(in_channel, hidden_channel, out_channel, output_pooling_size)

        concat_cells = sum([i * i for i in output_pooling_size]) * out_channel
        # print('concat_cells size >>> ', concat_cells)

        self.dense_layer_1 = nn.Linear(concat_cells, concat_cells//2)
        self.output_layer = nn.Linear(concat_cells//2, num_class)

    def forward(self, byte):
        single_feature_out = self.single_feature_conv_layer(byte)
        # print('Mal3D_single_feature_out shape >>> ', single_feature_out.shape, '\n')

        out = self.dense_layer_1(single_feature_out)
        # print('Mal3D_dense1_out shape >>> ', out.shape, '\n')

        out = self.output_layer(out)
        # print('Mal3D_output_out shape >>> ', out.shape, '\n')

        return out

if __name__ == '__main__':
    # Hyperparameter
    batch_size = 1
    epochs = 30

    image_height = 64  # summary 용
    image_width = 64  # summary 용

    in_channels = 1
    hidden_channels = 16
    out_channels = 32
    hidden_pooling_size = [10]
    output_pooling_size = [2, 1]
    num_classes = 10
    # learning_rate = 1e-3
    patience = 20
    used_loss = 'CE'  # CrossEntropy(CE), Class Balanced Loss(CB)
    hyperparameter = [hidden_channels, out_channels, hidden_pooling_size[0], sum(output_pooling_size), used_loss]

    model = Mal3S(in_channels, hidden_channels, out_channels, output_pooling_size, num_classes).to(device)
    # model = nn.DataParallel(model)  # GPU 병렬 설정
    summary(model, (in_channels, image_height, image_width))

    early_stopping = EarlyStopping(patience=patience, verbose=True, hyperparameter=hyperparameter)
    criterion = nn.CrossEntropyLoss()
    # optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    optimizer = optim.Adam(model.parameters(), lr=1e-4, weight_decay=1e-5, betas=(0.9, 0.99))

    # Dataset
    train_dataset = MalD3S_Dataset(mode='train', transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize([0.5], [0.5])]))
    valid_dataset = MalD3S_Dataset(mode='valid', transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize([0.5], [0.5])]))
    test_dataset = MalD3S_Dataset(mode='test', transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize([0.5], [0.5])]))

    train_dataloader = DataLoader(train_dataset, batch_size=batch_size, shuffle=False, drop_last=False, num_workers=32)
    valid_dataloader = DataLoader(valid_dataset, batch_size=batch_size, shuffle=False, drop_last=False, num_workers=32)
    test_dataloader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, drop_last=False, num_workers=32)

    print('----------------------------')
    print('>>> Dataset information <<<')
    print('Train dataset size : ', len(train_dataloader))
    print('Valid dataset size : ', len(valid_dataloader))
    print('Test dataset size : ', len(test_dataloader))
    print('----------------------------')

    recode_train_result = []
    recode_valid_result = []
    recode_test_result = []

    for epoch in range(epochs):
        start_time = time.time()
        # train
        model.train()
        train_cnt = 0  # 1 epoch 당 연산 수행 횟수
        train_loss = 0
        train_true = 0
        train_acc = 0

        for batch_idx, (image, label) in enumerate(train_dataloader):
            image, label = image.to(device), label.to(device)
            train_cnt += 1
            optimizer.zero_grad()
            output = model(byte=image).to(device)
            pred = torch.max(output, 1)[1]
            loss = criterion(output, label)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
            train_true += torch.sum(pred == label.data)

        train_loss = train_loss / train_cnt
        train_acc = train_true / (len(train_dataloader.dataset))
        recode_train_result.append([train_loss, train_acc.item()])

        # Validation
        model.eval()
        valid_cnt = 0  # 1 epoch 당 연산 수행 횟수
        valid_loss = 0
        valid_true = 0
        valid_acc = 0

        with torch.no_grad():
            for batch_idx, (image, label) in enumerate(valid_dataloader):
                image, label = image.to(device), label.to(device)

                valid_cnt += 1
                output = model(byte=image).to(device)
                pred = torch.max(output, 1)[1]
                loss = criterion(output, label)
                valid_loss += loss.item()
                valid_true += torch.sum(pred == label.data)

            valid_loss = valid_loss / valid_cnt
            valid_acc = valid_true / (len(valid_dataloader.dataset))
            recode_valid_result.append([valid_loss, valid_acc.item()])
            end_time = time.time()
            print('\nEpoch : %s [Time: %ssec]' % ((epoch + 1), (end_time - start_time)))
            print('Train >>> loss: %.8f | accuracy: %.6f' % (train_loss, train_acc))
            print('Valid >>> loss: %.8f | accuracy: %.6f' % (valid_loss, valid_acc))
            early_stopping(valid_loss, model)

    # Test
    model.load_state_dict(torch.load('./Checkpoint/Single_String_ft-%s_hc-%s_oc-%s_hp-%s_op-%s_loss-%s_checkpoint.pt' % (fastText_size, hyperparameter[0], hyperparameter[1], hyperparameter[2], hyperparameter[3], hyperparameter[4])))
    model.eval()

    test_cnt = 0  # 1 epoch 당 연산 수행 횟수
    test_loss = 0
    test_true = 0
    test_acc = 0
    test_pred = torch.LongTensor().to(device)

    test_image_cnt = 0  # 이미지 5개씩 묶기 위한 cnt
    test_images = []  # 이미지 5개씩 묶은 list

    with torch.no_grad():
        for batch_idx, (image, label) in enumerate(test_dataloader):
            image, label = image.to(device), label.to(device)
            test_cnt += 1
            output = model(byte=image).to(device)
            pred = torch.max(output, 1)[1]
            loss = criterion(output, label)
            test_loss += loss.item()
            test_true += torch.sum(pred == label.data)
            test_pred = torch.cat((test_pred, pred), dim=0)

        test_loss = test_loss / test_cnt
        test_acc = test_true / (len(test_dataloader.dataset))

    print('\nTest >>> loss: %.8f | accuracy: %.6f' % (test_loss, test_acc))

    test_raw_Label = []
    test_Data_Info = get_Data_Info('./Dataset/test.csv')

    for data_Info in test_Data_Info:
        test_raw_Label.append(data_Info[1])

    test_raw_Label = list(map(int, test_raw_Label))
    cm = confusion_matrix(test_raw_Label, test_pred.detach().cpu().numpy())
    cm_trans = cm.T
    '''
    precision = tp/(tp+fp)
    recall = tp/(tp+fn)
    f1_score = 2*(precision*recall)/(precision+recall)
    '''
    tp_list, fp_list, tn_list, fn_list = [], [], [], []
    precision_list, recall_list, f1_score_list = [], [], []

    for i in range(len(cm)):
        tp, fp, tn, fn = 0, 0, 0, 0
        for j in range(len(cm[i])):
            if i == j:
                tp += cm[i][j]
            elif i != j:
                fn += cm[i][j]
                fp += cm_trans[i][j]

        tp_list.append(tp)
        fn_list.append(fn)
        fp_list.append(fp)
        tn_list.append(cm.sum()-tp-fn-fp)
        precision_list.append(tp_list[i] / (tp_list[i] + fp_list[i]))
        recall_list.append(tp_list[i] / (tp_list[i] + fn_list[i]))
        f1_score_list.append(2 * (precision_list[i] * recall_list[i]) / (precision_list[i] + recall_list[i]))

    label_name = ['Benign', 'Ramnit', 'Lollipop', 'Kelihos_ver3', 'Vundo', 'Simda', 'Tracur', 'Kelihos_ver1', 'Obfuscator.ACY', 'Gatak']
    print_test_result = []
    print_test_result.append(['Test loss', test_loss])
    print_test_result.append(['Test accuracy', test_acc.item()])
    print_test_result.append(['\n'])
    print_test_result.append([' '] + label_name)

    for body_idx in range(len(cm)):
        print_test_result.append(([label_name[body_idx], cm[body_idx][0], cm[body_idx][1], cm[body_idx][2], cm[body_idx][3], cm[body_idx][4], cm[body_idx][5], cm[body_idx][6], cm[body_idx][7], cm[body_idx][8], cm[body_idx][9]]))

    print_test_result.append(['\n'])
    print_test_result.append([' '] + label_name)
    print_test_result.append(['TP'] + tp_list)
    print_test_result.append(['FP'] + fp_list)
    print_test_result.append(['TN'] + tn_list)
    print_test_result.append(['FN'] + fn_list)
    print_test_result.append(['Precision'] + precision_list)
    print_test_result.append(['Recall'] + recall_list)
    print_test_result.append(['F1 score'] + f1_score_list)

    with open('./Result/Single_String_ft-%s_hc-%s_oc-%s_hp-%s_op-%s_loss-%s_test_result.csv' % (fastText_size, hyperparameter[0], hyperparameter[1], hyperparameter[2], hyperparameter[3], hyperparameter[4]), 'w', newline='') as file:
        write = csv.writer(file)
        write.writerows(print_test_result)

    print_train_valid_result = [['epoch', 'train loss', 'train accuracy', 'valid loss', 'valid accuracy']]
    for i in range(epochs):
        print_train_valid_result.append([(i+1), recode_train_result[i][0], recode_train_result[i][1], recode_valid_result[i][0], recode_valid_result[i][1]])

    with open('./Result/Single_String_ft-%s_hc-%s_oc-%s_hp-%s_op-%s_loss-%s_train_valid_recode.csv' % (fastText_size, hyperparameter[0], hyperparameter[1], hyperparameter[2], hyperparameter[3],hyperparameter[4]), 'w', newline='') as file:
        write = csv.writer(file)
        write.writerows(print_train_valid_result)
