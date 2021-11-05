from app import app
from flask import render_template, redirect, url_for, session, request, json
import paramiko
import os.path
import sys
import requests
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# 로그인 정보
root_email, root_password = "asd@asd.com", "asd"

# SFTP
    # transport 열기
host, port = '220.149.241.75', 3302
transport = paramiko.Transport((host, port))
    # 사용사 인증
username, password = "aiiaabc_5", "aiia&abc!tjqj5"
transport.connect(None, username, password)
    # 시작
sftp = paramiko.SFTPClient.from_transport(transport)

@app.route('/')
@app.route('/irb')
def irb() :
    signin = False
    if 'IRB_signin' in session :
        signin = True
    return render_template('irb.html', IRB_signin=signin)

@app.route('/irb/process-signin', methods=['POST'])
def irb_process_signin() :
    values = request.get_json(force=True)
    email = values['email']
    password = values['password']

    if (root_email == email and root_password == password) :
        session['IRB_signin'] = True
        return redirect(url_for('irb'))
    else :
        return '<script>alert("Check Inputs");</script>'

@app.route('/irb/process-signout', methods=['POST'])
def irb_process_signout() :
    session.clear() # 모든 파이썬 세션 삭제
    return 'IRB Sign Out'




@app.route('/researcher-irb')
def researcher_irb() :
    inv = False
    if 'IRB_inv' in session :
        inv = True
    return render_template('researcher_irb.html', IRB_inv=inv)

@app.route('/researcher-irb/accept-invitation', methods=['POST'])
def researcher_irb_accept_invitation() :
    values = request.get_json(force=True)
    credential_definition_id = values['credential_definition_id']
    session['IRB_inv'] = credential_definition_id

    response = requests.get(f'http://0.0.0.0:8011/credential-definitions/created')
    print(response.json(), file=sys.stdout)
    return 'Researcher accepts IRB invitation'

@app.route('/researcher-provider')
def researcher_provider() :
    inv = False
    if 'Provider_inv' in session :
        inv = True
    return render_template('researcher_provider.html', Provider_inv=inv)

@app.route('/researcher-provider/accept-invitation', methods=['POST'])
def researcher_provider_accept_invitation() :
    values = request.get_json(force=True)
    session['Provider_inv'] = values
    return 'Researcher accepts Provider invitation'

@app.route('/researcher-consumer')
def researcher_consumer() :
    inv = False
    if 'Consumer_inv' in session :
        inv = True
    
    # credential 읽어오기
    current_path = os.getcwd() # 현재 working directory 경로 가져오기
    file_path = os.path.join(current_path, 'app', "file", "credential.json") # 경로 병합해 새 경로 생성
    f = open(file_path, 'r')
    credential = f.read()

    return render_template('researcher_consumer.html', Consumer_inv=inv, credential=credential)

@app.route('/researcher-consumer/accept-invitation', methods=['POST'])
def researcher_consumer_accept_invitation() :
    values = request.get_json(force=True)
    session['Consumer_inv'] = values
    return 'Researcher accepts Consumer invitation'





@app.route('/provider')
@app.route('/provider/invitation')
def provider_invitation() :
    cred = False
    if 'Researcher_cred_to_provider' in session :
        cred = True
    return render_template('provider_invitation.html', credential=cred)

@app.route('/provider/credential')
def provider_credential() :
    cred = False
    if 'Researcher_cred_to_provider' in session :
        cred = True
    return render_template('provider_credential.html', credential=cred)

@app.route('/provider/data')
def provider_data() :
    cred = False
    if 'Researcher_cred_to_provider' in session :
        cred = True

    return render_template('provider_data.html', credential=cred)

@app.route('/provider/receive-credential', methods=['POST'])
def provider_receive_credential() :
    credential = request.get_json(force=True)
    session['Researcher_cred_to_provider'] = credential
    return credential

@app.route('/provider/send-data-consumer', methods=['POST'])
def provider_send_credential() :
    file = request.get_json(force=True) # 웹 페이지로부터 선택한 파일 가져오기
    title = file['file'] # 파일의 제목만 추출

    sftp_path = f'/repo_test/provider/{title}' # SFTP 경로
    current_path = os.getcwd() # 현재 working directory 경로 가져오기
    file_path = os.path.join(current_path, 'app', 'file', title) # 경로 병합해 새 경로 생성

    sftp.get(sftp_path, file_path) # 파일 다운로드

    # 암호화
        # 1) 파일 내용 읽기
    body = file_read(file_path)
        # 2) 데이터, 키 2개씩 생성
    key1, key2, iv, hash1, hash2 = create_2key_and_2data(body)
        # 3) file 폴더에 credential을 저장
    ret = save_credential_in_file(current_path, key1, key2, iv)
        # 4) body1, body2 (=data) consumer SFTP로 전송
    send_data_consumerSFTP(hash1, hash2)

    return 'Data sent from Provider to Consumer'

@app.route('/provider/issue-credential', methods=['POST'])
def provider_issue_credential() :
    current_path = os.getcwd() # 현재 working directory 경로 가져오기
    cred_path = os.path.join(current_path, 'app', 'file', 'credential.json') # 경로 병합해 새 경로 생성

    with open(cred_path, 'r') as f :
        credential = f.read()
    return credential



@app.route('/consumer')
@app.route('/consumer/invitation')
def consumer_invitation() :
    signin = False
    cred = False
    if 'Consumer_signin' in session :
        signin = True
    return render_template('consumer_invitation.html', Consumer_signin=signin)

@app.route('/consumer/credential')
def consumer_credential() :
    signin = False
    if 'Consumer_signin' in session :
        signin = True
    return render_template('consumer_credential.html', Consumer_signin=signin)

@app.route('/consumer/data')
def consumer_data() :
    return render_template('consumer_data.html')

@app.route('/consumer/process-signin', methods=['POST'])
def consumer_process_signin() :
    values = request.get_json(force=True)
    email = values['email']
    password = values['password']

    if (root_email == email and root_password == password) :
        session['Consumer_signin'] = True
        return redirect(url_for('consumer_invitation'))
    else :
        return '<script>alert("Check Inputs");</script>'

@app.route('/consumer/process-signout', methods=['POST'])
def consumer_process_signout() :
    session.pop('Consumer_signin', None)
    return 'consumer Sign Out'

@app.route('/consumer/receive-credential', methods=['POST'])
def consumer_receive_credential() :
    credential = request.get_json(force=True)
    session['Researcher_cred_to_consumer'] = credential
    return credential









    ### security (Researcher가 선택한 데이터 credential로 만들기) ###
# 키 암호화 함수
def encrypt(key, iv, bMessage):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    tail = 16 - (len(bMessage) % 16)
    #print(tail)
    plain = bMessage + bytes(tail)
    #print(plain)

    cMessage = encryptor.update(plain) + encryptor.finalize()
    return cMessage

# 키 복호화 함수
def decrypt(key, iv, cMessage):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(cMessage) + decryptor.finalize()

# 암호화 함수
def twoChannelEncrytion(key1, key2, iv, body):
    # import os
    # key1 = os.urandom(32)
    # iv = os.urandom(16)
    # key2 = os.urandom(32)  
    split = [bytearray(), bytearray()]
    for i in range(len(body)):
        split[i%2].append(body[i])
    body1 = encrypt(key1, iv, split[0])
    body2 = encrypt(key2, iv, split[1])
    # return key1, key2, iv, body1, body2
    return body1, body2

# 복호화 함수
def twoChannelDecrytion(key1, key2, iv, body1, body2):
    split1 = decrypt(key1, iv, body1)
    split2 = decrypt(key2, iv, body2)
    body = bytearray()
    for i in range(len(split1)):
        body.append(split1[i])
        body.append(split2[i])
    return body

def twoChannelStore(body1, body2):
    current_path = os.getcwd() # 현재 working directory 경로 가져오기

    hash1 = "sCDC0109267107"
    hash1_path = os.path.join(current_path, 'app', "file", hash1) # 경로 병합해 새 경로 생성
    file1 = open(hash1_path, 'w')
    file1.write(body1)
    file1.close()
    hash2 = "secM0803220193"
    hash2_path = os.path.join(current_path, 'app', "file", hash2) # 경로 병합해 새 경로 생성
    file2 = open(hash2_path, 'w')
    file2.write(body2)
    file2.close()
    return hash1, hash2
    
def twoChannelLoad(hash1, hash2):
    current_path = os.getcwd() # 현재 working directory 경로 가져오기

    hash1_path = os.path.join(current_path, 'app', "file", hash1) # 경로 병합해 새 경로 생성
    file1 = open(hash1_path, 'r')
    body1 = file1.read()
    file1.close()

    hash2_path = os.path.join(current_path, 'app', "file", hash2) # 경로 병합해 새 경로 생성
    file2 = open(hash2_path, 'r')
    body2 = file2.read()
    file2.close()
    return body1, body2



# routes.py > provider_send_credential에서 사용하는 함수
def file_read(file_path) :
    body = '' # empty data content
    with open(file_path, "r") as f :
        body = f.read()
    body = body.encode('utf-8')
    f.close()
    return body

def create_2key_and_2data(body) :
    key1 = b64decode("othk6WkHQ4O6Iz//KZWpaM2fLXLQw80rD8Bt/XLtSuo=".encode('utf-8'))
    iv = b64decode("XYsr8+TbMFcCd9DHiCZGzg==".encode('utf-8'))
    key2 = b64decode("fbYeFx+06LRa47rZZH3Db6xO0rezOIitQ27r07ZEpbw=".encode('utf-8'))
    body1, body2 = twoChannelEncrytion(key1, key2, iv, body)

    hash1, hash2 = twoChannelStore(b64encode(body1).decode('utf-8'), b64encode(body2).decode('utf-8'))
    return key1, key2, iv, hash1, hash2

def save_credential_in_file(current_path, key1, key2, iv) :
    credential_path = os.path.join(current_path, 'app', "file", "credential.json") # 경로 병합해 새 경로 생성
    with open(credential_path, 'w', encoding='utf-8') as f :
        content = {
            'key1': b64encode(key1).decode('utf-8'),
            'key2': b64encode(key2).decode('utf-8'),
            'seed': b64encode(iv).decode('utf-8')
        }
        content = json.dumps(content, ensure_ascii=False, indent="\t") # json으로 변환
        f.write(content) # 파일에 쓰기
    f.close()
    return True

def send_data_consumerSFTP(hash1, hash2) :
    consumerSFTP = [f'/repo_test/consumer/{hash1}', f'/repo_test/consumer/{hash2}']
    print(consumerSFTP, file=sys.stdout)

    current_path = os.getcwd() # 현재 working directory 경로 가져오기
    file_path = []
    file_path.append(os.path.join(current_path, 'app', 'file', hash1))
    file_path.append(os.path.join(current_path, 'app', 'file', hash2))
    print(file_path, file=sys.stdout)

    sftp.put(file_path[0], consumerSFTP[0])
    sftp.put(file_path[1], consumerSFTP[1])