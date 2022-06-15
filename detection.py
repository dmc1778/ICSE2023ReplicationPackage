import random
import subprocess
import os
from csv import writer
from subprocess import Popen, PIPE
from time import process_time
import re


tools_name = ['flawfinder', 'cppcheck', 'rats']
user_name = ['mlpack', 'numpy', 'pandas-dev', 'pytorch', 'scipy', 'tensorflow']
this_project = os.getcwd()

analyzers_commands = [
                    'infer analyze -gcc -c ',
                    'flawfinder --context ',
                    'cppcheck --xml ',
                    'rats --quiet --xml -w 3 '
]

def filter_cpp_files(target_files):
    filtered = []
    for f in target_files:
        if f.endswith('.c') or f.endswith('.cc') or f.endswith('.cpp') or f.endswith('.hpp'):
            filtered.append(f)
    return filtered

def filter_test_files(target_files):
    filtered = []
    for f in target_files:
        if 'test' not in f:
            filtered.append(f)
    return filtered

def getListOfFiles(dirName):
    # create a list of file and sub directories 
    # names in the given directory 
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory 
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)         
    return allFiles        



def parse_output_project_level(data, tool_name):
    if tool_name == 'flawfinder':
        if re.findall(r'(No hits found)', data):
            return 'not detected'
        if re.findall(r'(Hits =)', data):
            return 'detected'

    if tool_name == 'cppcheck':
        if re.findall(r'(\<location file=)', data):
            return 'detected'
        else:
            return 'not detected'

    if tool_name == 'rats':
        if re.findall(r'(\<vulnerability\>)', data):
            return 'detected'
        else:
            return 'not detected'


def parse_output_known_vuln(data, tool_name, actual_cwe_id):
    if tool_name == 'flawfinder':
        if re.findall(r'(No hits found)', data):
            return 'not detected'
        if re.findall(r'(Hits =)', data):
            if re.findall(r'(\(CWE-[0-9]+\))', data):
                match_ = re.findall(r'(\(CWE-[0-9]+\))', data)
                if match_[0] == actual_cwe_id:
                    return 'true detected'
                else:
                    return 'detected'
            return 'detected'

    if tool_name == 'cppcheck':
        if re.findall(r'(\<location file=)', data):
            if re.findall(r'(cwe=\"[0-9]+\")', data):
                match_ = re.findall(r'(cwe=\"[0-9]+\")', data)
                if match_[0] == actual_cwe_id:
                    return 'true detected'
                else:
                    return 'detected'
        else:
            return 'not detected'

    if tool_name == 'rats':
        if re.findall(r'(\<vulnerability\>)', data):
            return 'detected'
        else:
            return 'not detected'

def project_level_detect():
    for root, dirs, _ in os.walk('ml_repos_cloned'):
        for _dir in dirs:
            try:
                current_repo = os.path.join(this_project, root, _dir)
                current_lib = os.path.join(current_repo, os.listdir(current_repo)[0])
                current_files = getListOfFiles(current_lib)
                current_files = filter_test_files(current_files)
                current_files = filter_cpp_files(current_files)
            
                # current_files = random.sample(current_files, 50)
                for j, t in enumerate(analyzers_commands):
                    for counter, file in enumerate(current_files):
                        print("Analyzed files: {}/{}, Library:{}, Tool:{}".format(counter, len(current_files), os.listdir(current_repo)[0] ,tools_name[j]))
                        h = process_time()
                        output = subprocess.getoutput(t+file)
                        elapsed_time = process_time() - h
                        output = [os.listdir(current_repo)[0], tools_name[j], output, elapsed_time]
                        res = parse_output_project_level(output[2], tools_name[j])
                        if res == 'detected':
                            with open('detection_results/project_level/'+os.listdir(current_repo)[0]+'.csv', 'a', newline='\n') as fd:
                                writer_object = writer(fd)
                                writer_object.writerow(output)
            except Exception as e:
                print(e)


def commit_level_detect():
    test_files_per_lib = os.listdir('known_vul_files')
    for n, lib in enumerate(test_files_per_lib):
        current_lib = os.path.join(this_project, 'vul_files', lib)
        for j, t in enumerate(analyzers_commands):
            for _,_,test_files in os.walk(current_lib):
                for file in test_files:
                    split_test_file_name = file.split('_')
                    current_test_file = os.path.join(current_lib, file)

                    h = process_time()
                    output = subprocess.getoutput(t+current_test_file)
                    
                    elapsed_time = process_time() - h

                    res = parse_output_known_vuln(output, tools_name[j], split_test_file_name[1])
                    try:
                        commit_link = 'https://github.com/'+user_name[n]+"/"+lib+'/commit/'+split_test_file_name[0]
                        output = [lib, tools_name[j] , split_test_file_name[1], output, elapsed_time, res, commit_link]
                        with open('detection_results/'+lib+'.csv', 'a', newline='\n') as fd:
                            writer_object = writer(fd)
                            writer_object.writerow(output)
                    except Exception as e:
                        print(e)



if __name__ == '__main__':
    project_level_detect()




