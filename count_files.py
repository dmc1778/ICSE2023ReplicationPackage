import os
from csv import writer

f = ['opennn', 'mlpack', 'numpy', 'pandas' ,'pytorch', 'lapack', 'scikit-learn', 'scipy', 'tensorflow']

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


this_project = os.getcwd()

def get_stat():
    for root, dir, file in os.walk(this_project+'/ml_repos_cloned'):
        for i, lib in enumerate(dir):
            current_lib = os.path.join(root, lib, f[i])
            current_lib_files = getListOfFiles(current_lib)
            related_files_with_test = filter_cpp_files(current_lib_files)
            related_files_final = filter_test_files(related_files_with_test)
            with open('./data/stat.csv', 'a', newline='\n') as fd:
                my_data = [i, f[i], len(current_lib_files), len(related_files_with_test), len(related_files_final)]
                writer_object = writer(fd)
                writer_object.writerow(my_data)
        break

def get_files():
    for root, dir, file in os.walk(this_project+'/ml_repos_cloned'):
        for i, lib in enumerate(dir):
            current_lib = os.path.join(root, lib, f[i])
            current_lib_files = getListOfFiles(current_lib)
            related_files_with_test = filter_cpp_files(current_lib_files)
            related_files_final = filter_test_files(related_files_with_test)
            with open('./data/files.csv', 'a', newline='\n') as fd:
                for item in related_files_final:
                    my_data = [i, f[i], item]
                    writer_object = writer(fd)
                    writer_object.writerow(my_data)
        break


def main():
    get_stat()
    #get_files()


if __name__ == '__main__':
    main()