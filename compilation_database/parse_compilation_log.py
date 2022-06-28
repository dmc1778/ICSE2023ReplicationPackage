import re, os, json, itertools

json_begin = '['
json_end = ']'

def write_to_file(output, jsonfile):
    for i, row in enumerate(output):
        jsonfile.write('{')
        jsonfile.write('\n')
        json.dump(row, jsonfile, indent=4)
        jsonfile.write(':')
        jsonfile.write(' ')
        jsonfile.write('[')
        jsonfile.write('\n')
        for j, sub_row in enumerate(output[row]):
            json.dump(sub_row, jsonfile, indent=4)
            if j != len(output[row])-1:
                jsonfile.write(',')
                jsonfile.write('\n')
        jsonfile.write('\n')
        jsonfile.write(']')
        jsonfile.write('\n')
        jsonfile.write('}')
        jsonfile.write(',')

def read_txt(fname):
    with open(fname, 'r') as fileReader:
        data = fileReader.read().splitlines()
    return data

def decompose_compilations(splitted_lines):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if bool(splitted_lines[j]) == False:
            indices.append(j)
        j += 1

    if len(indices) == 1:
        for i, item in enumerate(splitted_lines):
            if i != 0:
                super_temp.append(item)
        super_temp = [super_temp]
    else:
        i = 0
        j = 1
        while True:
            temp = [] 
            for row in range(indices[i], indices[j]):
                temp.append(splitted_lines[row])
            super_temp.append(temp)
            if j == len(indices)-1:
                temp = [] 
                for row in range(indices[j], len(splitted_lines)):
                    temp.append(splitted_lines[row])
                super_temp.append(temp)
                break
            i+= 1
            j+= 1

    return super_temp

def parse_numpy_logs():
    log_data = read_txt('compilation_database/numpy_command_log.txt')
    log_data_decomposed = decompose_compilations(log_data)

    output = {}

    for opt in log_data_decomposed:
        compile_opts = []
        file_paths = []
        for line in opt:
            if re.findall(r'(INFO\:\scompile\soptions\:)', line):
                splited_line = line.split("'")
                compile_opts.append(splited_line[1])
            if re.findall(r'(INFO\:\sx86\_64\-)', line):
                splited_file_path = line.split(" ")
                file_paths.append(splited_file_path[-1])
        c = list(itertools.product(compile_opts, file_paths))
        print(c)

def parse_pandas_logs():
    pass

def parse_scipy_logs():
    pass

if __name__ == '__main__':
    parse_numpy_logs()