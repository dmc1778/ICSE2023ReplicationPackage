import os, json
import pandas as pd

this_project = os.getcwd()

def count_vic_vfc():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs_json'

    for i, dir in enumerate(os.listdir(vic_path)):
        vic_lib_path = os.path.join(vic_path, dir)

        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)

        j = 0
        files = []
        commits = []
        for counter, item in enumerate(data):
            x = list(item.keys())   
            if bool(item[x[0]]):
                j += 1
                for k, v in item.items():
                    for sub_item in v:
                        for c in sub_item['previous_commits']:
                            commits.append(c[0])   
                        files.append(sub_item['file_path'])

        print('{} library has {} number of valid VFCs'.format(dir.split('_')[1].split('.')[0], j))
        print('{} library has {} number of VICs'.format(dir.split('_')[1].split('.')[0], len(commits)))
        print('{} library has {} number of unique VICs'.format(dir.split('_')[1].split('.')[0], len(set(commits))))
        print('{} library has {} number of vulnerable files'.format(dir.split('_')[1].split('.')[0], len(files)))
        print('{} library has {} number of unique vulnerable files'.format(dir.split('_')[1].split('.')[0], len(set(files))))
        print('################################################################################')
        

def parse_results():
    data = pd.read_csv('detection_results/workflow1/results_workflow1.csv')
    data = data[data.iloc[:, 11] == 'detected']
    data.to_csv('detection_results/workflow1/detected1.csv', sep=',', index=False)

    data = pd.read_csv('detection_results/workflow1/detected1.csv')
    data_diff = data[(data.iloc[:, 10] == 1) & (data.iloc[:, 1] == 'diff')]
    data_fixed = data[(data.iloc[:, 10] <= 5) & (data.iloc[:, 1] == 'fixed')]

    data_new = [data_diff, data_fixed]
    data_new = pd.concat(data_new)
    data_new.to_csv('detection_results/workflow1/limited_data.csv', sep=',', index=False)

    # data_fixed.to_csv('detection_results/workflow1/data_fixed.csv', sep=',', index=False)


if __name__ == '__main__':
    count_vic_vfc()