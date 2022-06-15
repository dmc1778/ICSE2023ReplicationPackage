import os
import numpy as np

def write_list_to_txt4(data, filename):
    with open(filename, "a", encoding='utf-8') as file:
        file.write(data+'\n')

def write_list_to_txt3(data, filename):
    with open(filename, "w", encoding='utf-8') as file:
        file.write(data+'\n')

def write_list_to_txt2(data, filename):
    with open(filename, "w") as file:
        for row in data:
            file.write(row+'\n')

def read_txt(fname):
    with open(fname, 'r') as fileReader:
        data = fileReader.read().splitlines()
    return data
        
def main():
    for root, dir, files in os.walk('./repos_phase1'):
        for file in files:
            current_file = os.path.join(root, file)
            data = read_txt(current_file) 
            data = set(data)
            filename = os.path.join('./repo_phase_1_uniques', file)
            write_list_to_txt2(data, filename)



if __name__ == '__main__':
    main()
