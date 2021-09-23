from multiprocessing import Process
import os
import time

def func1():
    os.system('python servidor.py')

def func2():
    os.system('python cliente.py')

if __name__ == '__main__':
  p1 = Process(target=func1)
  p1.start()
  time.sleep(10)
  p2 = Process(target=func2)
  p2.start()
  p1.join()
  p2.join()