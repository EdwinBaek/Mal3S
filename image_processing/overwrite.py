import os
import shutil

save_Dir_Path = 'C:/Users/ucloud/Desktop/extracted Data/'
modify_Dir_Path = 'C:/Users/ucloud/Desktop/raw data/final2/'

save_Dir_List = os.listdir(save_Dir_Path)
modify_Dir_List = os.listdir(modify_Dir_Path)

for save_File in save_Dir_List:
    for modify_File in modify_Dir_List:
        if save_File == modify_File:
            if os.path.getsize(save_Dir_Path+save_File) >= os.path.getsize(modify_Dir_Path+modify_File):
                os.remove(modify_Dir_Path+modify_File)
            else :
                os.remove(save_Dir_Path+save_File)

modify_Dir_List = os.listdir(modify_Dir_Path)
for move_File in modify_Dir_List:
    shutil.move(modify_Dir_Path + move_File, save_Dir_Path + move_File)

