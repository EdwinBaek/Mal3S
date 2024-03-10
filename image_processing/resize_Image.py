import os
import glob
from PIL import Image


def resize(path, size):
    images = glob.glob(path)

    for image in images:
        try:
            img = Image.open(image)
            img_resize = img.resize((size, size))
            title, ext = os.path.splitext(image)
            img_resize.save(title + ext)
        except OSError as e:
            print(image + ' image ' + str(e) + ' Error!')
            pass

def __main__():
    resize('./data/total_Img/*.jpg', 256)

__main__()