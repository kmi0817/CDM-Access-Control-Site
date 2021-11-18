# siteCode update 버전

1. Installation
```
pip3 install paramiko
pip3 install requests
```

2. SFTP directory info
```
1) provider SFTP 경로: /repo_list/provider
2) consumer SFTP 경로: /repo_list/consumer
```

3. Commands needed for starting Flask
```
export FLASK_APP=app
export FLASK_ENV=development
flask run
```

4. Changable Data in routes.py
- SFTP port, id, password, path
- IRB/Consumer id, password

5. Errors
1) [암호화, 복호화 코드 모듈화] 외부 모듈로 생성하여 routes.py에 import 하면 에러 발생 (circular import 인 듯함)

6. Reference
- 파일 다운로드: https://roytuts.com/how-to-download-file-using-python-flask/