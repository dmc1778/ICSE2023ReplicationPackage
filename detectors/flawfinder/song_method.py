
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

this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_FLAWFINDER = re.compile('\:(\d+)')
REG_RATS = re.compile('<vulnerability>')
REG_CPP_CHECK_LOC = re.compile('line=\"(\d+)\"')
REG_CPP_CHECK = re.compile('error id=')

FIND_CWE_IDENTIFIER = re.compile('CWE-(\d+)')
FIND_RATS_VUL_TYPE = re.compile('<type.*>((.|\n)*?)<\/type>')

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
        if detector_name == 'infer':
            if REG_LOC_FLAWFINDER.search(splitted_lines[j]):
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
    if 'test' not in commit.filename:
        diff_split = get_diff_header(commit.diff)
        if bool(commit.new_path):
            f_names[commit.new_path] = diff_split
        else:
            f_names[commit.old_path] = diff_split
    else:
        if 'test' not in commit.filename:
            diff_split = get_diff_header(commit.diff)
            if bool(commit.new_path):
                f_names[commit.new_path] = diff_split
            else:
                f_names[commit.old_path] = diff_split
    return f_names

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
    parsed_ouput = {}
    if re.findall(r'<location file=',  output):
        # x = re.findall(r'<error id=.*>((.|\n)*?)<\/error>', output)
        x = decompose_detections(output.split('\n'), 'cppcheck')
        for detection in x:
            detection = list(detection)
            # del detection[-1]
            # detection_split = detection[0].split('\n')
            for line in detection:
                if REG_CPP_CHECK_LOC.search(line):
                    y = int(REG_CPP_CHECK_LOC.search(line).group(1))
                    break
            parsed_ouput[x] = '\\n'.join(detection)
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
    parsed_ouput = {}
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
                    parsed_ouput[y] = detection
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
    parsed_ouput = {}
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

def run(test_file, detector_name):
    if detector_name == 'flawfinder':
        command_ = 'flawfinder --context '
    if detector_name == 'rats':
        command_ = 'rats --quiet --xml -w 3 '
    if detector_name == 'cppcheck':
        command_ = 'cppcheck --xml '
    if detector_name == 'infer':
        command_ = 'infer analyze -- gcc -c '
        
    start_time = time.time()
    output = subprocess.getoutput(command_+test_file)
    execution_time = time.time() - start_time
    return output, execution_time

def diff_based_matching(changed_lines, current_commit, detector_name):

    save_source_code(current_commit.source_code_before, 'vul', current_commit.filename)

    loc = len(current_commit.source_code_before.split('\n'))

    if os.path.isfile(os.path.join(this_project, 'vul_'+current_commit.filename)):
        [output, execution_time] = run(os.path.join(this_project, 'vul_'+current_commit.filename), detector_name)

        if detector_name == 'flawfinder':
            res = parse_flawfinder(output)

        if detector_name == 'cppcheck':
            res = parse_cppcheck(output)
        
        if detector_name == 'rats':
            res = parse_rats(output)

        detection_status = {'detected': []}
        if not isinstance(res[0], str):
            for loc, warning in res[0].items():
                detection_status['detected'].append(warning)

    subprocess.call('rm -rf '+this_project+'/vul_'+current_commit.filename, shell=True)

    return detection_status, current_commit, res, execution_time

def save_source_code(source_code, flag, filename):
    split_source_code = source_code.split('\n')
    with codecs.open(flag+'_'+filename, 'w') as f_method:
        for line in split_source_code:
            f_method.write("%s\n" % line)
        f_method.close()

def fixed_warning_base_matching(fix_commit, vul_commit, detector_name):


    #save_source_code(vul_file_object.source_code_before, 'fix', vul_file_object.filename)
    save_source_code(vul_commit.source_code_before, 'vul', vul_commit.filename)
    save_source_code(vul_commit.source_code, 'fix', vul_commit.filename)
        
    if os.path.isfile(this_project+'/vul_'+vul_commit.filename):
        [output1, execution_time1] = run(this_project+'/vul_'+vul_commit.filename, detector_name)

        if detector_name == 'flawfinder':
            res1 = parse_flawfinder(output1)

        if detector_name == 'cppcheck':
            res1 = parse_cppcheck(output1)
        
        if detector_name == 'rats':
            res1 = parse_rats(output1)

    if os.path.isfile(this_project+'/fix_'+vul_commit.filename):
        [output2, execution_time2] = run(this_project+'/fix_'+vul_commit.filename, detector_name)

        if detector_name == 'flawfinder':
            res2 = parse_flawfinder(output2)

        if detector_name == 'cppcheck':
            res2 = parse_cppcheck(output2)
        
        if detector_name == 'rats':
            res2 = parse_rats(output2)
            
    flag = False
    if not isinstance(res1[0], str) and isinstance(res2[0], str):
        flag = True

    subprocess.call('rm -rf '+this_project+'/fix_'+vul_commit.filename, shell=True)
    subprocess.call('rm -rf '+this_project+'/vul_'+vul_commit.filename, shell=True)

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


def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs_json'

    tools = ['flawfinder', 'rats']
    mappings_ = ['diff', 'fixed']

    for tool in tools:
        for mapping_ in mappings_:
            for i, dir in enumerate(os.listdir(vic_path)):
                if user_names[i] == 'tensorflow':
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

                # iterate over vulnerable inducing commits
                try:
                    for counter, item in enumerate(data):
                        x = list(item.keys())
                        current_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])
                        for mod in current_commit.modifications:
                            if 'test' not in mod.new_path or 'test' not in mod.filename:
                                cl = get_fix_file_names(mod)

                                if mapping_ == 'diff':
                                    detection_status, vul_file_object, res, execution_time = diff_based_matching(cl, mod, tool)
                                    if res == 'not detected':
                                        print('No vulnerable candidate detected!')
                                        my_data = [tool, 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0]
                                        my_data.append('not detected')

                                    else:
                                        data_list, j = combine_diff_results(detection_status)
                                        my_data = [tool, 'diff', dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]
                                        my_data = my_data + data_list
                                        
                                        for v in range(len(res[1])):
                                            vul_freq_data = [tool, dir.split('_')[1].split('.')[0]]
                                            vul_freq_data = vul_freq_data + [res[1][v]]
                                            with open('./detection_results/vul_frequency.csv', 'a', newline='\n') as fd:
                                                writer_object = writer(fd)
                                                writer_object.writerow(vul_freq_data)
                                        
                                    with open('./detection_results/results.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow(my_data)

                                if mapping_ == 'fixed':
                                    flag, vul_file_object, res1, res2, execution_time = fixed_warning_base_matching(cl, mod, tool)
                                
                                    if flag:
                                        data_list, j = combine_fixed_results(res1[0])
                                        my_data = [tool, 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, j]
                                        my_data = my_data + data_list
            
                                    else:
                                        my_data = [tool, 'fixed' , dir.split('_')[1].split('.')[0], execution_time, commit_base_link+x[0], commit_base_link+current_commit.hash, vul_file_object.filename, vul_file_object.new_path, vul_file_object.added, vul_file_object.removed, 0 , 'not detected']
                                                    
                                    with open('./detection_results/results.csv', 'a', newline='\n') as fd:
                                        writer_object = writer(fd)
                                        writer_object.writerow(my_data)

                                print('Running {} using {} method on {} Library, {}/{}'.format(tool, mapping_, dir.split('_')[1].split('.')[0], counter, len(data)))
                except Exception as e:
                    print(e)

                                

if __name__ == '__main__':
    main()