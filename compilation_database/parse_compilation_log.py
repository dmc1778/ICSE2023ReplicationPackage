from glob import glob
import re, os, json, itertools, pathlib, subprocess
from csv import writer

HERE = pathlib.Path(__file__).parent.absolute()
ROOT = HERE / "../../"
this_project = '/media/nimashiri/DATA/vsprojects/ICSE23'
json_begin = '['
json_end = ']'
user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']
FIND_TF_SECTORS = re.compile('\/usr\/bin\/gcc -U_FORTIFY_SOURCE ((.|\n)*?)TF2_BEHAVIOR=1')

class str2(str):
    def __repr__(self):
        # Allow str.__repr__() to do the hard work, then
        # remove the outer two characters, single quotes,
        # and replace them with double quotes.
        return ''.join(("'", super().__repr__()[1:-1], "'"))

def write_to_file_tf(output, jsonfile, j , log_data_decomposed):
    if j != len(log_data_decomposed) - 1:
        #for i, row in enumerate(output):
        jsonfile.write('\n')
        temp_dict = {'command': output}
        json.dump(temp_dict, jsonfile, indent=4)
        jsonfile.write(',')
    # else:
    #     #for i, row in enumerate(output):
    #     jsonfile.write('\n')
    #     temp_dict = {'command': output}
    #     json.dump(temp_dict, jsonfile, indent=4)
    #     if i != len(output) -1:
    #         jsonfile.write(',')

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

def read_txt_tf(fname):
    with open(fname, 'r') as fileReader:
        data = fileReader.read()
    return data

def decompose_compilations_tf(splitted_lines):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if re.findall(r'\/usr\/bin\/gcc -U_FORTIFY_SOURCE', splitted_lines[j]):
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

def remove_white_spaces(split_row):
    return list(filter(None, split_row))

def parse_infer(output):
    if re.findall(r'(No\sissues\sfound)', output):
        return 'No issues detected'
    elif re.findall(r'(\d+)\:\serror\:', output):
        return 'Detected'
    else:
        return 'Compilation error'

def write_list_to_txt4(data, filename):
    with open(filename, "a", encoding='utf-8') as file:
        file.write(data+'\n')

def remove_noise():
    pc = read_txt(this_project+'/compilation_database/parsed.txt')
    json_files = [f for f in os.listdir(os.path.join(this_project, 'compilation_database')) if f.endswith('.json')]
    # data = ['compilation_database/compile_commands_pytorch.json', 'compilation_database/compile_commands_mlpack.json']
    # data = ['compilation_database/compile_commands_tensorflow.json']
    for c, file in enumerate(json_files):
            root_path = os.path.join(this_project, 'ml_repos_cloned', file.split('_')[-1].split('.')[0], file.split('_')[-1].split('.')[0])
            with open(this_project+'/compilation_database/'+file, encoding='utf-8') as f:
                current_data = json.loads(f.read(), strict=False)
                    
            is_valid = False
            if file.split('_')[-1].split('.')[-2] == 'tensorflow':
                for i, row in enumerate(current_data):
                    if row['file'] not in pc:
                        write_list_to_txt4(row['file'], this_project+'/compilation_database/parsed.txt')
                        split_row = row['command'].split(' ')
                        split_row = remove_white_spaces(split_row)
                        split_row.remove(split_row[0])
                        for j, line in enumerate(list(split_row)):
                            if line == '-o':
                                split_row.remove(line)
                                split_row.remove(split_row[j])
                            if line == '-c':
                                f_path = split_row[j+1].split('/')
                            if f_path[0] == 'tensorflow' or f_path[0] == 'third_party':
                                is_valid = True
                                file_path = split_row[j+1]

                            if is_valid:
                                command_ = ' '.join(split_row)

                                command_ = command_.replace("'", '')

                                command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_
                                command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_
                                    
                                os.chdir(os.path.join(this_project, 'ml_repos_cloned' , 'tensorflow'))

                                subprocess.call(command_capture, shell=True)
                                output = subprocess.getoutput(command_analyze)
                                subprocess.call('rm -rf infer-out', shell=True)
                                subprocess.call('rm -rf *.o', shell=True)

                                is_valid = False

                                stat = parse_infer(output)

                                my_data = [file.split('_')[-1].split('.')[0], file_path, stat]

                                with open(this_project+'/compilation_database/infer_status.csv', 'a', newline='\n') as fd:
                                    writer_object = writer(fd)
                                    writer_object.writerow(my_data)
                    else:
                        print('Already analyzed!')
            else:
                for i, row in enumerate(current_data):
                        if os.path.isfile(current_data[i]['file']):
                            split_row = row['command'].split(' ')
                            if file.split('_')[-1].split('.')[-2] == 'numpy' or file.split('_')[-1].split('.')[-2] == 'pandas' or file.split('_')[-1].split('.')[-2] == 'scipy':
                                if row['file'] not in pc:
                                    write_list_to_txt4(row['file'], this_project+'/compilation_database/parsed.txt')
                                    try:
                                        os.chdir(os.path.join(this_project, 'ml_repos_cloned', user_names[c], file.split('_')[-1].split('.')[0]))

                                        command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+current_data[i]['command']+' '+ os.path.join(root_path, current_data[i]['file'])
                                        command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+current_data[i]['command']+' '+os.path.join(root_path, current_data[i]['file'])       

                                        subprocess.call(command_capture, shell=True)
                                        output = subprocess.getoutput(command_analyze)
                                        subprocess.call('rm -rf infer-out', shell=True)
                                        subprocess.call('rm -rf *.o', shell=True)

                                        stat = parse_infer(output)

                                        my_data = [file.split('_')[-1].split('.')[0], row['file'], stat]

                                        with open(this_project+'/compilation_database/infer_status.csv', 'a', newline='\n') as fd:
                                            writer_object = writer(fd)
                                            writer_object.writerow(my_data)
                                    except Exception as e:
                                        print(e)
                                else:
                                    print('Already analyzed!')

                            else:
                                    if row['file'] not in pc:
                                        write_list_to_txt4(row['file'], this_project+'/compilation_database/parsed.txt')
                                        try:
                                            new_list = []
                                            for j, line in enumerate(list(split_row)):
                                                if re.findall(r'\-I', line):
                                                        new_list.append(line)
                                                if re.findall(r'(\/usr\/bin\/c\+\+)', line) or re.findall(r'(\/usr\/bin\/cc)', line):
                                                        split_row.remove(line)
                                                if re.findall(r'(\-o)', line):
                                                        split_row.remove(line)
                                                if re.findall(r'(\.o)', line):
                                                        split_row.remove(line)
                                            current_data[i]['command'] = ' '.join(split_row)
                                            current_data[i]['command'] = ' '.join(split_row)

                                            command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+current_data[i]['command']
                                            command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+current_data[i]['command']  

                                            subprocess.call(command_capture, shell=True)
                                            output = subprocess.getoutput(command_analyze)
                                            subprocess.call('rm -rf infer-out', shell=True)
                                            subprocess.call('rm -rf *.o', shell=True)

                                            stat = parse_infer(output)

                                            my_data = [file.split('_')[-1].split('.')[0], row['file'], stat]
                                            
                                            with open(this_project+'/compilation_database/infer_status.csv', 'a', newline='\n') as fd:
                                                writer_object = writer(fd)
                                                writer_object.writerow(my_data)

                                        except Exception as e:
                                            print(e)
                                    else:
                                        print('Already analyzed!')

def parse_logs():
    out_dir = 'compilation_database'
    for root, dir, files in os.walk(out_dir):
        for file in files:
            if re.findall(r'(tensorflow\_command\_log.txt)', file):
                current_compilation_log = os.path.join(out_dir, file)
                if file == 'tensorflow_command_log.txt':
                    log_data = read_txt(current_compilation_log)
                    # log_data = read_txt_tf(current_compilation_log)
                    log_data_decomposed = decompose_compilations_tf(log_data)
                else:
                    log_data = read_txt(current_compilation_log)
                    log_data_decomposed = decompose_compilations(log_data)
                
                output = []
                lib_name = file.split('_')[0]
                out_json = os.path.join(out_dir, f'compile_commands_{lib_name}.json')
                jsonfile = open(out_json, 'a', encoding='utf-8')
                jsonfile.write(json_begin)

                if lib_name == 'tensorflow':
                    for j, opt in enumerate(log_data_decomposed):
                        print(j)
                        compile_opts = []
                        file_paths = []
                        #for line in opt:
                            # if re.findall(r'\/usr\/bin\/gcc -U_FORTIFY_SOURCE', line):
                                #compile_opts.append(line)
                                #break
                        #         splited_file_path = line.split(" ")
                        #         for n, l in enumerate(splited_file_path):
                        #             if l == '-c':
                        #                 file_paths.append(splited_file_path[n+1])
                        # c = list(itertools.product(compile_opts, file_paths))
                        # c = list(map(list, c))
                        # output = output + opt[0]
                        write_to_file_tf(opt[0], jsonfile, j , log_data_decomposed)
                    jsonfile.write(json_end)
                else:
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
    # parse_logs()
    remove_noise()