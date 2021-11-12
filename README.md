# siteCode update 버전

1. 설치 내용
```
pip3 install paramiko
pip3 install requests
```

2. SFTP 폴더
```
1) provider SFTP 경로: /repo_list/provider
2) consumer SFTP 경로: /repo_list/consumer
```

3. 플라스크 시작하기
```
export FLASK_APP=app
export FLASK_ENV=development
flask run
```

4. 사용자에 따라 변경 가능해야 하는 내용
- SFTP 포트, 아이디, 비밀번호, 경로 (모두 routes.py 파일에서 수정 가능)

5. 수정할 내용
- (1)
- Researcher가 선택한 데이터를, Provider의 SFTP에서 Consumer의 SFTP로 넘기기 전 credential (암호화) 과정
- 암호화에 필요한 함수를 외부 모듈로 생성하고자 함 (security.py 내에)
- 하지만 외부 모듈로 불리한 후 routes.py 에서 import 하니 오류 발생
- 원인 파악X -> 일단 routes.py 파일 내에 함수를 입력함
- (3) researcher가 provider한테 credential 제시할 때 어떤 swagger API 사용하는지? 아님 그냥 로컬 세션 스토리지 사용하는지? 일단 아무것도 안 하고 버튼만 누르면,,, 그렇게 됨.
- (4) provider/data에서 SFTP에 있는 파일들 제목을 직접 SFTP로부터 읽어올 수가X -> 일단 직접 적음

7. ** provider에서 credential accept하는 페이지 사용 안 했음 ㅋㅋ 수정해야지.