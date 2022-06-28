import re, os, json, itertools

json_begin = '['
json_end = ']'

def write_to_file(output, jsonfile, j , log_data_decomposed):
    if j != len(log_data_decomposed) - 1:
        for i, row in enumerate(output):
            jsonfile.write('\n')
            temp_dict = {'command': row[0], 'file': row[1]}
            json.dump(temp_dict, jsonfile, indent=4)
            jsonfile.write(',')
    else:
        for i, row in enumerate(output):
            jsonfile.write('\n')
            temp_dict = {'command': row[0], 'file': row[1]}
            json.dump(temp_dict, jsonfile, indent=4)
            if i != len(output) -1:
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

def parse_logs():
    out_dir = 'compilation_database'

    for root, dir, files in os.walk(out_dir):
        for file in files:
            if re.findall(r'(\_command\_log.txt)', file):
                current_compilation_log = os.path.join(out_dir, file)
                log_data = read_txt(current_compilation_log)
                log_data_decomposed = decompose_compilations(log_data)
                
                output = []
                lib_name = file.split('_')[0]
                out_json = os.path.join(out_dir, f'compile_commands_{lib_name}.json')
                jsonfile = open(out_json, 'a', encoding='utf-8')
                jsonfile.write(json_begin)

                for j, opt in enumerate(log_data_decomposed):
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
                    c = list(map(list, c))
                    output = output + c
                    write_to_file(output, jsonfile, j , log_data_decomposed)
                jsonfile.write(json_end)


if __name__ == '__main__':
    parse_logs()