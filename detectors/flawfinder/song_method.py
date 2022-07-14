
from fnmatch import fnmatch
import string
from charset_normalizer import detect
from numpy import diff, isin
from py import code
from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
import os, json, re, subprocess, codecs
from csv import writer
import time

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']

_extensions = ['cc', 'cpp', 'hpp', 'h', 'c', 'cu']

this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_FLAWFINDER = re.compile('\:(\d+)')
REG_RATS = re.compile('<vulnerability>')
REG_CPP_CHECK_LOC = re.compile('line=\"(\d+)\"')
REG_CPP_CHECK = re.compile('error id=')

FIND_CWE_IDENTIFIER = re.compile('CWE-(\d+)')
FIND_RATS_VUL_TYPE = re.compile('<type.*>((.|\n)*?)<\/type>')

class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)

def decompose_detections(splitted_lines, detector_name):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if detector_name == 'flawfinder':
            if REG_LOC_FLAWFINDER.search(splitted_lines[j]):
                indices.append(j)
            j += 1
        if detector_name == 'cppcheck':
            if REG_CPP_CHECK.search(splitted_lines[j]):
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

def parse_cppcheck(output):
    parsed_ouput = Dictlist()
    if re.findall(r'<location file=',  output):
        # x = re.findall(r'<error id=.*>((.|\n)*?)<\/error>', output)
        detections = decompose_detections(output.split('\n'), 'cppcheck')
        for detection in detections:
            detection = list(detection)
            # del detection[-1]
            # detection_split = detection[0].split('\n')
            for line in detection:
                if REG_CPP_CHECK_LOC.search(line):
                    y = int(REG_CPP_CHECK_LOC.search(line).group(1))
                    break
            parsed_ouput[y] = '\\n'.join(detection)
        return parsed_ouput
    else:
        return 'not detected'

def find_rat_types(warning):
    if re.findall(r'<type.*>((.|\n)*?)<\/type>', warning):
        x = list(re.findall(r'<type.*>((.|\n)*?)<\/type>', warning)[0])
        del x[-1]
    if re.findall(r'resulting in a\s(.*?)\.', warning):
        x = re.findall(r'resulting in a\s(.*?)\.', warning)
    return x

def parse_rats(output):
    cwe_final_list = []
    parsed_ouput = Dictlist()
    if re.findall(r'(<vulnerability\>)', output):
        x = re.findall(r'<vulnerability.*>((.|\n)*?)<\/vulnerability>', output)
        for detection in x:
            detection = list(detection)
            del detection[1]
            cwe_list = find_rat_types(detection[0])
            detection_split = detection[0].split('\n')
            cwe_final_list = cwe_final_list + cwe_list
            for line in detection_split:
                if re.findall(r'<line.*>((.|\n)*?)<\/line>', line):
                    y = int(re.findall(r'<line.*>((.|\n)*?)<\/line>', line)[0][0])
                    parsed_ouput[y] = detection[0]
        return [parsed_ouput, cwe_final_list]
    else:
        return 'not detected'

def find_regex_groups(warning):
    cwe_list = []
    v = '\\n'.join(warning)
    if re.findall(r'CWE-(\d+)', v):
        x = re.findall(r'CWE-(\d+)', v)
    for cwe_ in x:
        cwe_list.append('CWE-'+cwe_)
    return cwe_list

def parse_flawfinder(output):
    cwe_final_list = []
    parsed_ouput = Dictlist()
    if re.findall(r'(No hits found)', output):
        return 'not detected'
    if re.findall(r'(Hits =)', output):
        detections = decompose_detections(output.split('\n'), 'flawfinder')
        for detection in detections:
            cwe_list = find_regex_groups(detection)
            cwe_final_list = cwe_final_list + cwe_list
            for line in detection:
                # extra looping here, should be resolved
                if REG_LOC_FLAWFINDER.search(line):
                    x = int(REG_LOC_FLAWFINDER.search(line).group(1))
                    break
            parsed_ouput[x] = '\\n'.join(detection) 
    return [parsed_ouput, cwe_final_list]

def search_for_compile_command(test_file, library_name):
    with open(f'compilation_database/compile_commands_{library_name}.json', encoding='utf-8') as f:
        compile_options = json.loads(f.read(), strict=False)
    print('dd')

def run(test_file, detector_name, library_name):
    if detector_name == 'flawfinder':
        command_ = 'flawfinder --context '
    if detector_name == 'rats':
        command_ = 'rats --quiet --xml -w 3 '
    if detector_name == 'cppcheck':
        command_ = 'cppcheck --xml '
        
    start_time = time.time()
    output = subprocess.getoutput(command_+test_file)
    execution_time = time.time() - start_time

    return output, execution_time

def _match(cl, loc):
    super_list = []
    flag_full = False
    flag_partial = False
    for sk, sub_cl in cl.items():
        super_list.append(tuple(sub_cl))
    if any(lower <= loc <= upper for (lower, upper) in super_list):
        flag_full = True
    if any(lower > loc or loc > upper for (lower, upper) in super_list):
        flag_partial = True
    return flag_full, flag_partial


def diff_based_matching(changed_lines, current_commit, detector_name, library_name):

    save_source_code(current_commit.source_code_before, 'vul', current_commit.filename)

    loc = len(current_commit.source_code_before.split('\n'))

    if os.path.isfile(os.path.join(this_project, 'vul_'+current_commit.filename)):
        [output, execution_time] = run(os.path.join(this_project, 'vul_'+current_commit.filename), detector_name, library_name)

        if detector_name == 'flawfinder':
            res = parse_flawfinder(output)

        if detector_name == 'cppcheck':
            res = parse_cppcheck(output)
        
        if detector_name == 'rats':
            res = parse_rats(output)
        
        # detection_status = {'detected': []}
        detection_status = {'full_match': [], 'partial_match': []}
        if not isinstance(res[0], str):
            for loc, warning in res[0].items():
                # detection_status['detected'].append(warning)
                for k, cl in changed_lines.items():
                    [flag_full, flag_partial] = _match(cl, loc)
                    if flag_full:
                        detection_status['full_match'].append(warning)
                    if flag_partial:
                        detection_status['partial_match'].append(warning)
                    

    subprocess.call('rm -rf '+this_project+'/vul_'+current_commit.filename, shell=True)

    return detection_status, current_commit, res, execution_time

def save_source_code(source_code, flag, filename):
    split_source_code = source_code.split('\n')
    with codecs.open(flag+'_'+filename, 'w') as f_method:
        for line in split_source_code:
            f_method.write("%s\n" % line)
        f_method.close()

def fixed_warning_base_matching(fix_commit, vul_commit, detector_name, library_name):
    #save_source_code(vul_file_object.source_code_before, 'fix', vul_file_object.filename)
    save_source_code(vul_commit.source_code_before, 'vul', vul_commit.filename)
    
    out = []    
    if os.path.isfile(this_project+'/vul_'+vul_commit.filename):
        [output1, execution_time1] = run(this_project+'/vul_'+vul_commit.filename, detector_name, library_name)

        if detector_name == 'flawfinder':
            res1 = parse_flawfinder(output1)

        if detector_name == 'cppcheck':
            res1 = parse_cppcheck(output1)
        
        if detector_name == 'rats':
            res1 = parse_rats(output1)

    subprocess.call('rm -rf '+this_project+'/vul_'+vul_commit.filename, shell=True)
   
    save_source_code(vul_commit.source_code, 'fix', vul_commit.filename)

    if os.path.isfile(this_project+'/fix_'+vul_commit.filename):
        [output2, execution_time2] = run(this_project+'/vul_'+vul_commit.filename, detector_name, library_name)

        if detector_name == 'flawfinder':
            res2 = parse_flawfinder(output2)

        if detector_name == 'cppcheck':
            res2 = parse_cppcheck(output2)
        
        if detector_name == 'rats':
            res2 = parse_rats(output2)

    if not isinstance(res1, str):  
        set_1 = set(res1[1])
        set_2 = set(res2[1])

        wfixed = set_1 - set_2
        out.append(wfixed)
        if bool(wfixed):
            # x = find_wfix(wfixed, res1, detector_name)
            #out.append(x)
            flag = True
    else:
        flag = False

    subprocess.call('rm -rf '+this_project+'/fix_'+vul_commit.filename, shell=True)
    

    return flag, vul_commit, res1, res2, execution_time1+execution_time2, out

def find_wfix(wfixed, res1, detector_name):
    output = {}
    wfix = list(wfixed)
    flat_list = sorted({x for v in res1[0].values() for x in v})
    for item1 in wfix:
        for item2 in flat_list:
            if re.findall(r'('+item1+r')', item2):
                if detector_name == 'flawfinder':
                    output[int(REG_LOC_FLAWFINDER.search(item2).group(1))] = item2
                if detector_name == 'rats':
                    for line in item2.split('\n'):
                        if re.findall(r'<line.*>((.|\n)*?)<\/line>', line):
                            y = int(re.findall(r'<line.*>((.|\n)*?)<\/line>', line)[0][0])
                    cwe_list = find_rat_types(item2)
                    if item1 in cwe_list:
                        output[y] = item2
                if detector_name == 'cppcheck':
                    output[int(REG_CPP_CHECK_LOC.search(item2).group(1))] = item2     
    return output

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

    for tool in ['flawfinder', 'rats', 'cppcheck']:
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
                                    
                                    print('Running {} using {} method on {} Library, {}/{}'.format(tool, mapping_, dir.split('_')[1].split('.')[0], counter, len(data)))

                                    if mapping_ == 'diff':
                                        detection_status, vul_file_object, res, execution_time = diff_based_matching(cl, mod, tool, user_names[i])
                                        if res == 'not detected':
                                            print('No vulnerable candidate detected!')
                                            my_data = [_id,tool, 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0]
                                            my_data.append('not detected')

                                        elif res == 'compilation error':
                                            print('No vulnerable candidate detected!')
                                            my_data = [_id, tool, 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0]
                                            my_data.append('compilation error')

                                        else:
                                            data_list, j = combine_diff_results(detection_status)
                                            my_data = [_id, tool, 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]
                                            my_data = my_data + data_list
                                                
                                            for v in range(len(res[1])):
                                                vul_freq_data = [tool, dir.split('_')[1].split('.')[0]]
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

                                    if mapping_ == 'fixed':
                                        flag, vul_file_object, res1, res2, execution_time, wfix = fixed_warning_base_matching(cl, mod, tool, user_names[i])
                                            
                                        if flag:
                                            data_list, j = combine_fixed_results(res1[0])
                                            my_data = [_id, tool, 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]

                                            my_data = my_data + [list(wfix[0])]
                                            my_data = my_data + data_list

                                        if res1 == 'not detected' or res1 == 'not detected':
                                            my_data = [_id, tool, 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0 , 'not detected']
                                             
                                        cl_list = [_id] + cl_list

                                        with open('./detection_results/change_info.csv', 'a', newline='\n') as fd:
                                                writer_object = writer(fd)
                                                writer_object.writerow(cl_list)

                                        with open('./detection_results/results.csv', 'a', newline='\n') as fd:
                                            writer_object = writer(fd)
                                            writer_object.writerow(my_data)

                                else:
                                    with open('./detection_results/filtered_files.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow([dir.split('_')[1].split('.')[0], x[0], mod.new_path, mod.filename])

                except Exception as e:
                    print(e)


if __name__ == '__main__':
    main()