from posixpath import split
import sys, os, re, subprocess, json
from pydriller import GitRepository as PyDrillerGitRepo
from csv import writer
import time, codecs

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']


_extensions = ['cc', 'cpp', 'c', 'cu']

this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_INFER = re.compile('(\d+)\:\serror\:')
REG_VUL_TYPE_INFER = re.compile('error\:(.*)')

def decompose_detections(splitted_lines, detector_name):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if detector_name == 'infer':
            if REG_LOC_INFER.search(splitted_lines[j]):
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


def get_patches(splitted_lines):
    change_info = {}
    i = 0
    for line in splitted_lines:
        if REG_CHANGED.match(line):
            i += 1
            addStart = int(REG_CHANGED.search(line).group(1))
            addedLines = int(REG_CHANGED.search(line).group(2))
            deletedStart = int(REG_CHANGED.search(line).group(3))
            deletedLines = int(REG_CHANGED.search(line).group(4))
                        
            start = deletedStart
            if(start == 0):
                start += 1
    
            end = addStart+addedLines-1
            change_info[i] = [deletedStart, deletedStart+deletedLines]

    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if re.findall(r'(@@)',splitted_lines[j]):
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
            for row in range(indices[i]+1, indices[j]):
                temp.append(splitted_lines[row])
            super_temp.append(temp)
            if j == len(indices)-1:
                temp = [] 
                for row in range(indices[j]+1, len(splitted_lines)):
                    temp.append(splitted_lines[row])
                super_temp.append(temp)
                break
            i+= 1
            j+= 1
    return super_temp, change_info



def get_diff_header(diff):
    code_lines = diff.split('\n')
    [super_temp, change_info] = get_patches(code_lines)
    return change_info


def get_fix_file_names(commit):
    f_names = {}
    raw_name = []
    if 'test' not in commit.filename:
        diff_split = get_diff_header(commit.diff)
        if bool(commit.new_path):
            f_names[commit.new_path] = diff_split
            raw_name.append(commit.new_path)
        else:
            f_names[commit.old_path] = diff_split
            raw_name.append(commit.old_path)
    else:
        if 'test' not in commit.filename:
            diff_split = get_diff_header(commit.diff)
            if bool(commit.new_path):
                f_names[commit.new_path] = diff_split
                raw_name.append(commit.new_path)
            else:
                f_names[commit.old_path] = diff_split
                raw_name.append(commit.old_path)
    return f_names, raw_name

def get_prev_file_names(repository_path, items):
    f_names = {}
    for k, value in items.items():
        for item in value:
            for prev_commit in item['previous_commits']:
                x = PyDrillerGitRepo(repository_path).get_commit(prev_commit[0])
                for modification in x.modifications:
                    if 'test' not in modification.filename:
                        diff_split = get_diff_header(modification.diff)
                        if bool(modification.new_path):
                            f_names[modification.new_path] = diff_split
                        else:
                            f_names[modification.old_path] = diff_split
    return f_names

def parse_infer(output):
    cwe_final_list = []
    parsed_output = {}

    if re.findall(r'(No\sissues\sfound)', output):
        return 'not detected'
    elif re.findall(r'(\d+)\:\serror\:', output):
        detections = decompose_detections(output.split('\n'), 'infer')
        for detection in detections:
            for line in detection:
                if REG_LOC_INFER.search(line):
                    x = int(REG_LOC_INFER.search(line).group(1))
                    cwe_final_list = cwe_final_list + [REG_VUL_TYPE_INFER.search(line).group(1)]
                    break
            parsed_output[x] = '\\n'.join(detection)
        return [parsed_output, cwe_final_list]
    else:
        return 'compilation error'

def find_regex_groups(warning):
    cwe_list = []
    v = '\\n'.join(warning)
    if re.findall(r'CWE-(\d+)', v):
        x = re.findall(r'CWE-(\d+)', v)
    for cwe_ in x:
        cwe_list.append('CWE-'+cwe_)
    return cwe_list

def remove_white_spaces(split_row):
    return list(filter(None, split_row))

def build_global_compile_option(compile_options):
    print('d')

def search_for_compile_command(test_file, library_name):
    find_opt = False
    output = []
    with open(this_project+'/compilation_database/compile_commands_'+library_name+'.json', encoding='utf-8') as f:
        compile_options = json.loads(f.read(), strict=False)

    glob_compile_option = build_global_compile_option(compile_options)

    if library_name == 'tensorflow':
        for opt in compile_options:
            split_row = opt['command'].split(' ')
            for j, line in enumerate(list(split_row)):
                if line == '-c':
                    f_path = split_row[j+1].split('/')
            if os.path.join(f_path[-2], f_path[-1]) == os.path.join(test_file.split('/')[-2], test_file.split('/')[-1]):
                find_opt = True
                output.append(opt)
                break
    else:
        for opt in compile_options:
            if os.path.join(opt['file'].split('/')[-2], opt['file'].split('/')[-1]) == os.path.join(test_file.split('/')[-2], test_file.split('/')[-1]):
                find_opt = True
                output.append(opt)
                break
    if find_opt:
        return output
    else:
        return False

def run(library_name, opt, filename, full_check):
    # command_capture = f'infer --keep-going -- gcc {compile_options} -c '
    # command_analyze = f'infer analyze -- gcc {compile_options} -c '

    if library_name == 'tensorflow':
        split_row = opt['command'].split(' ')
        split_row = remove_white_spaces(split_row)
        split_row.remove(split_row[0])
        split_row.remove(split_row[-1])
        split_row.remove(split_row[-1])
        split_row.remove(split_row[-1])
        # for j, line in enumerate(list(split_row)):
        #     if line == '-o':
        #         split_row.remove(line)
        #         split_row.remove(split_row[j])
        #     if line == '-c':
        #         split_row.remove(line)
        #         split_row.remove(split_row[j])

        command_ = ' '.join(split_row)

        command_ = command_.replace("'", '')

        if full_check:
            command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
            command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
        else:                           
            command_capture = 'infer --keep-going -- gcc '+command_+' '+filename
            command_analyze = 'infer analyze -- gcc '+command_+' '+filename

        os.chdir(this_project)

        start_time = time.time()
        subprocess.call(command_capture, shell=True)
        output = subprocess.getoutput(command_analyze)
        execution_time = time.time() - start_time

        subprocess.call('rm -rf infer-out', shell=True)
        subprocess.call('rm -rf *.o', shell=True)
 
    else:
        split_row = opt['command'].split(' ')
        if library_name == 'numpy' or library_name == 'pandas' or library_name == 'scipy':
            try:
                os.chdir(this_project)

                if full_check:
                    command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+opt['command']+' '+filename
                    command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+opt['command']+' '+filename      
                else:
                    command_capture = 'infer --keep-going -- gcc '+opt['command']+' '+filename
                    command_analyze = 'infer analyze -- gcc '+opt['command']+' '+filename      

                start_time = time.time()
                subprocess.call(command_capture, shell=True)
                output = subprocess.getoutput(command_analyze)
                execution_time = time.time() - start_time

                subprocess.call('rm -rf infer-out', shell=True)
                subprocess.call('rm -rf *.o', shell=True)

            except Exception as e:
                print(e)
        else:
            try:
                new_list = []
                split_row = remove_white_spaces(split_row)
                split_row.remove(split_row[0])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.append('-c')

                command_ = ' '.join(split_row)
                
                if full_check:
                    command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
                    command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
                else:
                    command_capture = 'infer --keep-going -- gcc '+command_+' '+filename
                    command_analyze = 'infer analyze -- gcc '+command_+' '+filename


                start_time = time.time()
                subprocess.call(command_capture, shell=True)
                output = subprocess.getoutput(command_analyze)
                execution_time = time.time() - start_time

                subprocess.call('rm -rf infer-out', shell=True)
                subprocess.call('rm -rf *.o', shell=True)

            except Exception as e:
                print(e)

    return output, execution_time

def diff_based_matching(changed_lines, current_commit, detector_name, library_name, opt, full_check):

    save_source_code(current_commit.source_code_before, current_commit.filename)

    loc = len(current_commit.source_code_before.split('\n'))

    if os.path.isfile(os.path.join(this_project,current_commit.filename)):
        [output, execution_time] = run(library_name, opt, current_commit.filename, full_check)
        
        res = parse_infer(output)

        detection_status = {'detected': []}
        if not isinstance(res[0], str):
            for loc, warning in res[0].items():
                detection_status['detected'].append(warning)
                # for k, cl in changed_lines.items():
                #     if cl[0] <= loc <= cl[1]:
                #         detection_status['full_match'].append(warning)
                #     elif loc <= cl[0] or loc >= cl[1]:
                #         detection_status['partial_match'].append(warning)
                #     else:
                #         detection_status['mismatch'].append(warning)

    subprocess.call('rm -rf '+this_project+'/'+current_commit.filename, shell=True)

    return detection_status, current_commit, res, execution_time

def save_source_code(source_code, filename):
    split_source_code = source_code.split('\n')
    with codecs.open(filename, 'w') as f_method:
        for line in split_source_code:
            f_method.write("%s\n" % line)
        f_method.close()

def fixed_warning_base_matching(fix_commit, vul_commit, detector_name, library_name, opt, full_check):
    #save_source_code(vul_file_object.source_code_before, 'fix', vul_file_object.filename)
    save_source_code(vul_commit.source_code_before, vul_commit.filename)
    
        
    if os.path.isfile(os.path.join(this_project, vul_commit.filename)):
     
        [output1, execution_time1] = run(library_name, opt, vul_commit.filename, full_check)
        
        res1 = parse_infer(output1)

    subprocess.call('rm -rf '+os.path.join(this_project, vul_commit.filename), shell=True)
    
    save_source_code(vul_commit.source_code, vul_commit.filename)

    if os.path.isfile(os.path.join(this_project, vul_commit.filename)):
        [output2, execution_time2] = run(library_name, opt, vul_commit.filename, full_check)

        res2 = parse_infer(output2)
            
    flag = False
    if not isinstance(res1[0], str) and isinstance(res2[0], str):
        flag = True

    subprocess.call('rm -rf '+os.path.join(this_project, vul_commit.filename), shell=True)
    

    return flag, vul_commit, res1, res2, execution_time1+execution_time2

def combine_fixed_results(detection_status):
    data_list = []
    data_list.append('detected')
    j = 0
    for k, v in detection_status.items():
        j += 1
        if bool(v):
            data_list.append(v)
    return data_list, j

def combine_diff_results(detection_status):
    data_list = []
    j = 0
    for k, v in detection_status.items():
        if bool(v):
            data_list.append(k)
            for item in v:
                j += 1
                data_list.append(item)
    return data_list, j

def changed_lines_to_list(cl):
    global_list = []
    for k, v in cl.items():
        for sk, sv in v.items():
            global_list = global_list + sv
    return global_list

def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs'
    full_check = True

    _id = 0

    for mapping_ in ['diff', 'fixed']:
        for i, dir in enumerate(os.listdir(vic_path)):
            
            if user_names[i] == 'tensorflow' or user_names[i] == 'pytorch':
                repository_path = this_project+'/ml_repos_cloned/'+user_names[i]
            else:
                repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]

            v = "https://github.com/{0}/{1}{2}".format(user_names[i], dir.split('_')[1].split('.')[0],'.git')

            commit_base_link = "https://github.com/{0}/{1}/{2}/".format(user_names[i], dir.split('_')[1].split('.')[0], 'commit')

            if not os.path.exists(repository_path):
                subprocess.call('git clone '+v+' '+repository_path, shell=True)
                    
            vic_lib_path = os.path.join(vic_path, dir)

                    # load vulnerable inducing commits
            with open(vic_lib_path, 'r', encoding='utf-8') as f:
                data = json.loads(f.read(),strict=False)

            try:
                for counter, item in enumerate(data):
                    _id += 1
                    x = list(item.keys())
                    current_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])
                    for mod in current_commit.modifications:
                        if 'test' not in mod.new_path and 'test' not in mod.filename and mod.filename.split('.')[-1] in _extensions:
                            cl, raw_name = get_fix_file_names(mod)
                            cl_list = changed_lines_to_list(cl)
                            opt = search_for_compile_command(raw_name[0], dir.split('_')[1].split('.')[0])
                            
                            print('Running {} using {} method on {} Library, {}/{}'.format('infer', mapping_, dir.split('_')[1].split('.')[0], counter, len(data)))

                            if mapping_ == 'diff' and opt:
                                detection_status, vul_file_object, res, execution_time = diff_based_matching(cl, mod, 'infer', user_names[i], opt[0], full_check)
                                if res == 'not detected':
                                    print('No vulnerable candidate detected!')
                                    my_data = [_id,'infer', 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0]
                                    my_data.append('not detected')

                                elif res == 'compilation error':
                                    print('No vulnerable candidate detected!')
                                    my_data = [_id, 'infer', 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0]
                                    my_data.append('compilation error')

                                else:
                                    data_list, j = combine_diff_results(detection_status)
                                    my_data = [_id, 'infer', 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]
                                    my_data = my_data + data_list
                                           
                                    for v in range(len(res[1])):
                                        vul_freq_data = ['infer', dir.split('_')[1].split('.')[0]]
                                        vul_freq_data = vul_freq_data + [res[1][v]]
                                        vul_freq_data = [_id] + vul_freq_data

                                        with open('./detection_results/vul_frequency.csv', 'a', newline='\n') as fd:
                                            writer_object = writer(fd)
                                            writer_object.writerow(vul_freq_data)
                                            
                                with open('./detection_results/results.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow(my_data)
                                
                                cl_list = [_id] + cl_list

                                with open('./detection_results/change_info.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow(cl_list)

                            if mapping_ == 'fixed' and opt:
                                flag, vul_file_object, res1, res2, execution_time = fixed_warning_base_matching(cl, mod, 'infer', user_names[i], opt[0], full_check)
                                    
                                if flag:
                                    data_list, j = combine_fixed_results(res1[0])
                                    my_data = [_id, 'infer', 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]
            
                                    my_data = my_data + data_list
                                    
                
                                elif res1 == 'not detected' or res2 == 'not detected':
                                    my_data = [_id, 'infer', 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0 , 'not detected']
                             

                                elif res1 == 'compilation error' or res2 == 'compilation error':
                                    my_data = [_id, 'infer', 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0 , 'compilation error']
                                                        
                                cl_list = [_id] + cl_list

                                with open('./detection_results/change_info.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow(cl_list)

                                with open('./detection_results/results.csv', 'a', newline='\n') as fd:
                                    writer_object = writer(fd)
                                    writer_object.writerow(my_data)

                            if mapping_ != 'fixed' and not opt:
                                with open('./detection_results/compile_options_failed.csv', 'a', newline='\n') as fd:
                                    writer_object = writer(fd)
                                    writer_object.writerow([dir.split('_')[1].split('.')[0], x[0], mod.new_path, mod.filename])
                        else:
                            with open('./detection_results/filtered_files.csv', 'a', newline='\n') as fd:
                                writer_object = writer(fd)
                                writer_object.writerow([dir.split('_')[1].split('.')[0], x[0], mod.new_path, mod.filename])

            except Exception as e:
                print(e)


if __name__ == '__main__':
    main()