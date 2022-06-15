
import pandas as pd
import csv, json

json_begin = '['
json_end = ']'

lib_names = ['mlpack', 'scipy', 'tensorflow', 'pytorch', 'sickit-learn', 'pandas', 'numpy']

def get_bfc_data_dataframe():
    

    data = pd.read_csv('data/vul_data.csv')

    for lib in lib_names:
        jsonfile = open('data/bug_fix_'+lib+'.json', 'w', encoding='utf-8')
        jsonfile.write(json_begin)
        lib_data = data[data.iloc[:, 0] == lib]
        result = lib_data.to_json(orient="records")
        parsed = json.loads(result)
        for i, item in enumerate(parsed):
            c_split = item['fix_commit_hash'].split('/')
            repo_name = c_split[3]+'/'+c_split[4]
            item['bug_fix_hash'] = c_split[-1]
            new_row = {'fix_commit_hash': c_split[-1], 'repo_name':repo_name}
            json.dump(new_row, jsonfile, indent=4) 
            if i != len(parsed)-1:
                jsonfile.write(',')
                jsonfile.write('\n')
        jsonfile.write(json_end)

def get_bfc():
  
    csvfile = open('data/vul_data.csv', 'r', encoding='utf-8')
    
    fieldnames = ("library", "CWE_id", 'fix_commit_hash')
    reader = csv.DictReader(csvfile, fieldnames)

    x = list(reader)
    for lib in lib_names:
        jsonfile = open('data/bug_fix_'+lib+'.json', 'w', encoding='utf-8')
        jsonfile.write(json_begin)
    
        for i, row in enumerate(x):
            c_split = row['fix_commit_hash'].split('/')
            repo_name = c_split[3]+'/'+c_split[4]
            row['bug_fix_hash'] = c_split[-1]
            new_row = {'fix_commit_hash': c_split[-1], 'repo_name':repo_name}
            json.dump(new_row, jsonfile, indent=4)
            if i != len(x)-1:
                jsonfile.write(',')
                jsonfile.write('\n')
        jsonfile.write(json_end)

if __name__ == '__main__':
    get_bfc_data_dataframe()