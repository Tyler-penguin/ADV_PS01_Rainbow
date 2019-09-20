import os, hashlib, csv, bcrypt, scrypt, argon2

def generate_key_pbkdf2(uid, password, rounds=10000):
    current_line = None
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'
    with open(my_dir + 'pbkdf2_output.csv', 'r+') as f:
        while current_line != '':
            current_line = f.readline()
            if current_line.split(',')[0] == uid:
                print('Entry not added: UID already exists')
                return
        salt = os.urandom(64)
        digest = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, rounds).hex()

        f.write(f'{uid},{digest},{salt},{rounds}\n')

def generate_key_bcrypt(uid, password):
    current_line = None
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'

    with open(my_dir + 'bcrypt_output.csv', 'r+') as f:
        while current_line != '':
            current_line = f.readline()
            if current_line.split(',')[0] == uid:
                print('Entry not added: UID already exists')
                return
        salt = bcrypt.gensalt()
        digest = bcrypt.hashpw(password.encode('utf-8'), salt)
        f.write(f'{uid},{digest},{salt}\n')

def generate_key_scrypt(uid, password):
    current_line = None
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'

    with open(my_dir + 'scrypt_output.csv', 'r+') as f:
        while current_line != '':
            current_line = f.readline()
            if current_line.split(',')[0] == uid:
                print('Entry not added: UID already exists')
                return
        salt = os.urandom(64)
        digest = scrypt.hash(password, salt).hex()
        f.write(f'{uid},{digest},{salt}\n')

def generate_key_argon2(uid, password):
    current_line = None
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'

    with open(my_dir + 'argon2_output.csv', 'r+') as f:
        while current_line != '':
            current_line = f.readline()
            if current_line.split(',')[0] == uid:
                print('Entry not added: UID already exists')
                return
        digest = argon2.PasswordHasher().hash(password).replace(',', '|')
        f.write(f'{uid},{digest}\n')



def add_many_to_output(filename, hash, rounds=10000):
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'
    with open(my_dir + filename, 'r') as f:
        f.readline()
        read_csv= csv.reader(f)
        for row in read_csv:
            if hash == 'pbkdf2':
                generate_key_pbkdf2(row[0], row[1], rounds)
            elif hash == 'bcrypt':
                generate_key_bcrypt(row[0], row[1])
            elif hash == 'scrypt':
                generate_key_scrypt(row[0], row[1])
            elif hash == 'argon2':
                generate_key_argon2(row[0], row[1])


def check_password(uid, password, function, filename):
    my_dir = os.path.dirname(os.path.realpath(__file__)) + '/'
    with open(my_dir + filename, 'r') as f:
        read_csv= csv.reader(f)
        check_info = None
        for row in read_csv:
            if row[0] == uid:
                check_info = row
                break
    if not check_info:
        return False

    elif function == 'pbkdf2':
        salt = bytes(row[2][2:-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
        return (hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, int(check_info[3])).hex() == check_info[1])

    elif function == 'bcrypt':
        return bcrypt.checkpw(password.encode('utf-8'), bytes(row[1][2:-1], 'utf-8'))

    elif function == 'scrypt':
        salt = bytes(row[2][2:-1], 'utf-8').decode('unicode-escape').encode('ISO-8859-1')
        return (scrypt.hash(password, salt).hex() == check_info[1])

    elif function == 'argon2':
        try:
            return (argon2.PasswordHasher().verify(check_info[1].replace('|', ','), password))
        except:
            return False

    else:
        print('HashError: Hash function is not implemented')
        raise SystemExit

add_many_to_output('pbkdf2_uid_pwd_list_for2ndpart.csv', 'argon2')
print(check_password('xenu3', 'e66582d4', 'argon2', 'argon2_output.csv'))
