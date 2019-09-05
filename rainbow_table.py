import os, csv
from hashlib import sha1 as hash

def get_pwds(filename, length):
    pwd_list = []
    my_dir = os.path.dirname(os.path.realpath(__file__))
    with open(my_dir + '/' + filename, 'r') as f:
        for line in f:
            pwd = line.strip()
            if len(pwd) == length:
                pwd_list.append(pwd)
    return pwd_list

def hash_pwds(pwd_list):
    pwd_dict = {}
    for pwd in pwd_list:
        hash_word = pwd
        for i in range(5):
            hash_word = hash(hash_word.encode('utf-8')).hexdigest()[:8]
        pwd_dict[hash_word] = pwd
    return pwd_dict

def use_table(pwd_hash, pwd_dict):
    hash_word = pwd_hash[:8]
    for i in range(5):

        if hash_word in pwd_dict:
            dict_pwd = pwd_dict[hash_word]
            for j in range(4-i):
                dict_pwd = hash(dict_pwd.encode('utf-8')).hexdigest()[:8]
            break
        hash_word = hash(hash_word.encode('utf-8')).hexdigest()[:8]
    return dict_pwd

def find_pwds(pwd_file, target_file, length):
    my_dir = os.path.dirname(os.path.realpath(__file__))
    pwd_list = get_pwds(pwd_file, length)
    pwd_dict = hash_pwds(pwd_list)

    hash_list = []
    with open(my_dir + '/' + target_file, 'r') as f:
        f.readline()
        read_csv= csv.reader(f)
        for row in read_csv:
            pwd = use_table(row[2], pwd_dict)
            print(*[row[0], pwd, row[2]])

    print(pwd)

find_pwds('500-most-common_passwords.txt', 'target_hash_list.csv', 8)
