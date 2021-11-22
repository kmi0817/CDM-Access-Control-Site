from paramiko.ssh_exception import SSHException
from app import app
from flask import render_template, session, request, json, send_file
import paramiko
import random
from time import time
import os.path
import requests
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# 로그인 정보
root_email, root_password = "asd@asd.com", "asd"

# SFTP 정보
host, port = '220.149.241.75', 3302
username, password = "aiiaabc_5", "aiia&abc!tjqj5"

# 폴더 경로
path = os.getcwd()
provider_path = path + '/app/provider_file'
provider_sftp_path = '/repo_test/provider'

consumer_path = path + '/app/consumer_file'
consumer_sftp_path = '/repo_test/consumer'

@app.route('/')
@app.route('/irb')
def irb() :
    signin = False
    if 'IRB_signin' in session :
        signin = True
    return render_template('irb.html', IRB_signin=signin)

@app.route('/irb/process-signinout', methods=['POST', 'DELETE'])
def irb_process_signinout() :
    if request.method == 'POST' :
        values = request.get_json(force=True)
        email = values['email']
        password = values['password']

        if (root_email == email and root_password == password) :
            session['IRB_signin'] = True
            ret = 'SUCCESS'
        else :
            ret = 'FAIL'
        return ret

    elif request.method == 'DELETE' :
        if 'irb_createInvitation' in session :
            conn_id = session['irb_createInvitation']['conn_id']
            with requests.delete(f'http://0.0.0.0:8011/connections/{conn_id}') as irb :
                print(irb.json())
        session.clear() # 모든 파이썬 세션 삭제
        return 'IRB Sign Out'

@app.route('/create-invitation/<server>', methods=['POST'])
def create_invitation_server(server) :
    if server == 'irb' :
        port = 8011
    elif server == 'provider' :
        port = 8051
    elif server == 'consumer' :
        port = 8061

    with requests.post(f'http://0.0.0.0:{port}/connections/create-invitation') as create_res :
        invitation = create_res.json()['invitation']
        conn_id = create_res.json()['connection_id']

    session[f'{server}_createInvitation'] = {
        'invitation': invitation,
        'conn_id': conn_id
    }
    return 'SUCCESS'

## credential-definition 등록 과정
# @app.route('/irb/create-creddef', methods=['POST'])
# def irb_create_schema() :
#     # Schmea Creation
#     version = format(
#             "%d.%d.%d"
#             % (random.randint(1, 101), random.randint(1, 101), random.randint(1, 101))
#     )

#     schema_body = {
#         "schema_name": "IRB schema",
#         "schema_version": version,
#         "attributes": ["name", "affiliation", "role",
#             "GCP", "IRB_no", "approved_date", "timestamp"],
#     }

#     with requests.post('http://0.0.0.0:8011/schemas', json=schema_body) as schema_res :
#         schema_id = schema_res.json()['schema_id']

#     # Credential-Definition Creation
#     support_revocation = False
#     TAILS_FILE_COUNT=100
#     credential_definition_body = {
#         "schema_id": schema_id,
#         "support_revocation": support_revocation,
#         "revocation_registry_size": TAILS_FILE_COUNT,
#     }

#     with requests.post('http://0.0.0.0:8011/credential-definitions',json=credential_definition_body) as creddef_res :
#         credential_definition_id = creddef_res.json()['credential_definition_id']

#     # session['IRB_createCreddef'] = {
#     #     'schema_id': schema_id,
#     #     'credential_definition_id' : credential_definition_id
#     # }
    
#     return 'SUCCESS'




@app.route('/researcher-irb')
def researcherIrb() :
    invitation = False
    my_did = False
    cred_def_ids = False
    if 'irb_createInvitation' in session :
        invitation = session['irb_createInvitation']['invitation']
    if 'Researcher_irbreceiveInvitation' in session :
        my_did = session['Researcher_irbreceiveInvitation']['my_did']
        with requests.get('http://0.0.0.0:8011/credential-definitions/created') as created_res :
            cred_def_ids = created_res.json()['credential_definition_ids']
            cred_def_ids = set(cred_def_ids)
    return render_template('researcher_irb.html', invitation=invitation, my_did=my_did, cred_def_ids=cred_def_ids)

@app.route('/receive-invitation/<server>', methods=['POST'])
def receive_invitation_server(server) :
    if f'{server}_createInvitation' in session :
        invitation = session[f'{server}_createInvitation']['invitation']

        with requests.post('http://0.0.0.0:8031/connections/receive-invitation', json=invitation) as receive_res :
            my_did = receive_res.json()['my_did']
        session[f'Researcher_{server}receiveInvitation'] = {
            "my_did" : my_did
        }
        return 'OK'

    else :
        return 'FAIL'

@app.route('/researcher-irb/issue-credential', methods=['POST'])
def researcherIrb_issue_credential() :
    values = request.get_json(force=True)
    cred_def_id = values['credential_definition_id']

        ## 직접 등록한 credential-definition에 맞춰 credential 발급
    cred_attrs=  {
        "name": "Alice",
        "affiliation": "CNUH",
        "role": "PI",
        "GCP": "1",
        "IRB_no": "2021-0008",
        "approved_date": "2021-03-28",
        "timestamp": str(int(time()))
    }
    CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
    cred_preview = {
        "@type": CRED_PREVIEW_TYPE,
        "attributes": [
            {"name": n, "value": v}
            for (n, v) in cred_attrs.items()
        ]
    }
    exchange_tracing = False
    conn_id = session['irb_createInvitation']['conn_id']
    offer_request = {
        "connection_id": conn_id,
        "comment": f"Offer on cred def id {cred_def_id}",
        "auto_remove": False,
        "credential_preview": cred_preview,
        "filter": {"indy": {"cred_def_id": cred_def_id}},
        "trace": exchange_tracing
    }
    with requests.post('http://localhost:8011/issue-credential-2.0/send-offer', json=offer_request) as offer_res :
        cred_ex_id = offer_res.json()['cred_ex_id']
    session['IRB_issueCredential'] = {
        "cred_ex_id": cred_ex_id
    }
    return 'OK'

@app.route('/researcher-provider')
def researcher_provider() :
    invitation = False
    my_did = False
    cred_ex_ids = False
    if 'provider_createInvitation' in session :
        invitation = session['provider_createInvitation']['invitation']
    if 'Researcher_providerreceiveInvitation' in session :
        my_did = session['Researcher_providerreceiveInvitation']['my_did']

        with requests.get('http://0.0.0.0:8031/issue-credential-2.0/records') as records_res :
            records = records_res.json()['results']
            cred_ex_ids = [] # list
            for record in records :
                cred_ex_ids.append(record['cred_ex_record']['cred_ex_id'])
            
    return render_template('researcher_provider.html', invitation=invitation, my_did=my_did, cred_ex_ids=cred_ex_ids)

@app.route('/researcher-provider/send-credential', methods=['POST'])
def researcher_provider_send_credential() :
    credential = request.get_json(force=True)
    session['provider_sendCredential'] = credential # provider에게 전달할 credential
    return 'OK'

@app.route('/researcher-consumer')
def researcher_consumer() :
    invitation = False
    my_did = False
    credential = False
    if 'consumer_createInvitation' in session :
        invitation = session['consumer_createInvitation']['invitation']
    if 'Researcher_consumerreceiveInvitation' in session :
        my_did = session['Researcher_consumerreceiveInvitation']['my_did']
    if 'Provider_issueCredential' in session :
        credential = session['Provider_issueCredential']

    return render_template('researcher_consumer.html', invitation=invitation, my_did=my_did, credential=credential)

@app.route('/researcher-consumer/send-credential', methods=['POST'])
def researcher_consumer_send_credential() :
    credential = request.get_json(force=True)
    session['consumer_sendCredential'] = credential # consumer에게 전달할(=제시할) credenti
    return 'OK'



@app.route('/provider')
@app.route('/provider/invitation')
def provider_invitation() :
    authorization = False
    if 'Provider_receiveCredential' in session :
        authorization = True
    return render_template('provider_invitation.html', authorization=authorization)

@app.route('/provider/credential')
def provider_credential() :
    credential = False
    authorization = False
    if 'provider_sendCredential' in session :
        credential = session['provider_sendCredential'] # provider에게 전달할 credential
    if 'Provider_receiveCredential' in session :
        authorization = True
    return render_template('provider_credential.html', credential=credential, authorization=authorization)

@app.route('/provider/data')
def provider_data() :
    authorization = False
    if 'Provider_receiveCredential' in session :
        authorization = True

        try : # SFTP
            transport = paramiko.Transport((host, port)) # transport 열기
            transport.connect(None, username, password) # 사용사 인증
            sftp = paramiko.SFTPClient.from_transport(transport) # 시작

            file_list = sftp.listdir(provider_sftp_path) # provider SFTP 내 파일 목록 가져오기
            file_dict = dict() # 빈 딕셔너리
            index = 1
            for file in file_list :
                file_dict[index] = file # 딕셔너리에 파일 추가
                index = index + 1
            if sftp :
                sftp.close()
            if transport :
                transport.close()
        except SSHException :
            print('### SFTPClien error ###')
            file_list = ['Unable to load files in SFTP']

        
    return render_template('provider_data.html', authorization=authorization, file_dict=file_dict)

@app.route('/provider/receive-credential', methods=['POST'])
def provider_receive_credential() :
    credential = request.get_json(force=True)
    session['Provider_receiveCredential'] = credential
    return 'OK'

@app.route('/provider/send-data-consumer', methods=['POST'])
def provider_send_credential() :
    file = request.get_json(force=True) # 웹 페이지로부터 선택한 파일 가져오기
    title = file['file'] # 파일의 제목만 추출
    session['selected_file'] = title # 세션 등록

    file_path = providerSFTP_get(title) # SFTP로부터 파일 가져오기

    # 암호화
        # 1) 파일 내용 읽기
    body = file_read(file_path)
        # 2) 데이터, 키 2개씩 생성
    key1, key2, iv, hash1, hash2 = create_2key_and_2data(body)
        # 3) file 폴더에 credential을 저장
    save_credential_in_file(key1, key2, iv)
        # 4) body1, body2 (=data) consumer SFTP로 전송
    providerSFTP_send_data_consumerSFTP(hash1, hash2)

    return 'OK'

@app.route('/provider/issue-credential', methods=['POST'])
def provider_issue_credential() :
    cred_path = os.path.join(provider_path, 'credential.json')
    with open(cred_path, 'r') as f :
        credential = f.read()
    session['Provider_issueCredential'] = credential
    return 'OK'



@app.route('/consumer')
@app.route('/consumer/invitation')
def consumer_invitation() :
    signin = False
    if 'Consumer_signin' in session :
        signin = True
    return render_template('consumer_invitation.html', Consumer_signin=signin)

@app.route('/consumer/credential')
def consumer_credential() :
    signin = False
    credential = False
    if 'Consumer_signin' in session :
        signin = True
    if 'consumer_sendCredential' in session : # researcher가 consumer에게 제시한 credential
        credential = session['consumer_sendCredential']
    return render_template('consumer_credential.html', Consumer_signin=signin, credential=credential)

@app.route('/consumer/data')
def consumer_data() :
    signin = False
    if 'Consumer_signin' in session :
        signin = True

    if 'Consumer_receiveCredential' in session :
        hash1 = "sCDC0109267107"
        hash2 = "secM0803220193"
        consumerSFPT_get_body(hash1, hash2) # SFTP에서 로컬로 파일 다운로드

        body1, body2 = twoChannelLoad(hash1, hash2) # 파일 암호화된 body 가져오기
        body1 = b64decode(body1.encode('utf-8'))
        body2 = b64decode(body2.encode('utf-8'))

        data_credential = session['Consumer_receiveCredential']
        key1 = b64decode(data_credential['key1'].encode('utf-8'))
        key2 = b64decode(data_credential['key2'].encode('utf-8'))
        iv = b64decode(data_credential['seed'].encode('utf-8'))

        body = twoChannelDecrytion(key1, key2, iv, body1, body2)
        body = body.decode('utf-8').replace('\u0000', '') # byte array -> string

        title = session['selected_file']
        file_path = os.path.join(consumer_path, title)
        if os.path.exists(file_path) == False : # 파일 없으면 Consumer SFTP에 파일 업로드
            with open(file_path, 'w') as f :
                f.write(body)
            sftp_path = os.path.join(consumer_sftp_path, title) # SFTP 경로

            try: # SFTP
                transport = paramiko.Transport((host, port)) # transport 열기
                transport.connect(None, username, password) # 사용사 인증
                sftp = paramiko.SFTPClient.from_transport(transport) # 시작

                sftp.put(file_path, sftp_path) # 파일 다운로드

                if sftp :
                    sftp.close()
                if transport :
                    transport.close()
            except SSHException :
                print('### SFTPClient error ###')

        return render_template('consumer_data.html', Consumer_signin=signin, file=body)
    else :
        return render_template('consumer_data.html', Consumer_signin=signin)

@app.route('/consumer/process-signinout', methods=['POST', 'DELETE'])
def consumer_process_signinout() :
    if request.method == 'POST' :
        values = request.get_json(force=True)
        email = values['email']
        password = values['password']

        if (root_email == email and root_password == password) :
            session['Consumer_signin'] = True
            ret = 'SUCCESS'
        else :
            ret = 'FAIL'
        return ret

    elif request.method == 'DELETE' :
        if 'consumer_createInvitation' in session :
            conn_id = session['consumer_createInvitation']['conn_id']
            with requests.delete(f'http://0.0.0.0:8061/connections/{conn_id}') as irb :
                print(irb.json())
        session.pop('consumer_createInvitation', None)
        session.pop('Researcher_consumerreceiveInvitation', None)
        session.pop('Consumer_signin', None)
        session.pop('consumer_sendCredential', None)
        session.pop('Consumer_receiveCredential', None)
        return 'Consumer Sign Out'

@app.route('/consumer/receive-credential', methods=['POST'])
def consumer_receive_credential() :
    credential = request.get_json(force=True)
    session['Consumer_receiveCredential'] = credential
    return 'OK'

@app.route('/consumer/data-download')
def consumer_data_download() :
    # 파일 생성
    file_title = session['selected_file']
    file_path = os.path.join(consumer_path, file_title)

    return send_file(file_path, as_attachment=True)








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
    hash1 = "sCDC0109267107"
    hash1_path = os.path.join(provider_path, hash1) # 경로 병합해 새 경로 생성
    file1 = open(hash1_path, 'w')
    file1.write(body1)
    file1.close()
    hash2 = "secM0803220193"
    hash2_path = os.path.join(provider_path, hash2) # 경로 병합해 새 경로 생성
    file2 = open(hash2_path, 'w')
    file2.write(body2)
    file2.close()
    return hash1, hash2
    
def twoChannelLoad(hash1, hash2):
    current_path = os.getcwd() # 현재 working directory 경로 가져오기

    hash1_path = os.path.join(consumer_path, hash1) # 경로 병합해 새 경로 생성
    file1 = open(hash1_path, 'r')
    body1 = file1.read()
    file1.close()

    hash2_path = os.path.join(consumer_path, hash2) # 경로 병합해 새 경로 생성
    file2 = open(hash2_path, 'r')
    body2 = file2.read()
    file2.close()
    return body1, body2



# routes.py > provider_send_credential에서 사용하는 함수
def file_read(file_path) :
    body = '' # empty data content
    with open(file_path, 'r') as f :
        body = f.read()
    body = body.encode('utf-8')
    return body

def create_2key_and_2data(body) :
    key1 = b64decode("othk6WkHQ4O6Iz//KZWpaM2fLXLQw80rD8Bt/XLtSuo=".encode('utf-8'))
    iv = b64decode("XYsr8+TbMFcCd9DHiCZGzg==".encode('utf-8'))
    key2 = b64decode("fbYeFx+06LRa47rZZH3Db6xO0rezOIitQ27r07ZEpbw=".encode('utf-8'))
    body1, body2 = twoChannelEncrytion(key1, key2, iv, body)

    hash1, hash2 = twoChannelStore(b64encode(body1).decode('utf-8'), b64encode(body2).decode('utf-8'))
    return key1, key2, iv, hash1, hash2

def save_credential_in_file(key1, key2, iv) :
    credential_path = os.path.join(provider_path, "credential.json") # 경로 병합해 새 경로 생성
    with open(credential_path, 'w', encoding='utf-8') as f :
        content = {
            'key1': b64encode(key1).decode('utf-8'),
            'key2': b64encode(key2).decode('utf-8'),
            'seed': b64encode(iv).decode('utf-8')
        }
        content = json.dumps(content, ensure_ascii=False, indent="\t") # json으로 변환
        f.write(content) # 파일에 쓰기



def providerSFTP_get(title) :
    sftp_path = os.path.join(provider_sftp_path, title) # SFTP 경로
    file_path = os.path.join(provider_path, title) # 경로 병합해 새 경로 생성

    try: # SFTP
        transport = paramiko.Transport((host, port)) # transport 열기
        transport.connect(None, username, password) # 사용사 인증
        sftp = paramiko.SFTPClient.from_transport(transport) # 시
        sftp.get(sftp_path, file_path) # 파일 다운로드

        if sftp :
            sftp.close()
        if transport :
            transport.close()
    except SSHException :
        print('### SFTPClient error ###')
    return file_path

def providerSFTP_send_data_consumerSFTP(hash1, hash2) :
    consumerSFTP = [f'{consumer_sftp_path}/{hash1}', f'{consumer_sftp_path}/{hash2}']

    file_path = []
    file_path.append(os.path.join(provider_path, hash1))
    file_path.append(os.path.join(provider_path, hash2))

    try: # SFTP
        transport = paramiko.Transport((host, port)) # transport 열기
        transport.connect(None, username, password) # 사용사 인증
        sftp = paramiko.SFTPClient.from_transport(transport) # 시
        sftp.put(file_path[0], consumerSFTP[0])
        sftp.put(file_path[1], consumerSFTP[1])
        if sftp :
            sftp.close()
        if transport :
            transport.close()
    except SSHException :
        print('### SFTPClient error ###')


def consumerSFPT_get_body(hash1, hash2) :
    consumerSFTP = [f'{consumer_sftp_path}/{hash1}', f'{consumer_sftp_path}/{hash2}']
    file_path = []
    file_path.append(os.path.join(consumer_path, hash1))
    file_path.append(os.path.join(consumer_path, hash2))

    try: # SFTP
        transport = paramiko.Transport((host, port)) # transport 열기
        transport.connect(None, username, password) # 사용사 인증
        sftp = paramiko.SFTPClient.from_transport(transport) # 시
        sftp.get(consumerSFTP[0], file_path[0])
        sftp.get(consumerSFTP[1], file_path[1])
        if sftp :
            sftp.close()
        if transport :
            transport.close()
    except SSHException :
        print('### SFTPClient error ###')
