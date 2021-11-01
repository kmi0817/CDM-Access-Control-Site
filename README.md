# siteCode update 버전

1. 설치 내용
```
pip3 install paramiko
pip3 install ...
```

2. 사용자에 따라 변경 가능해야 하는 내용
- SFTP 포트, 아이디, 비밀번호, 경로 (모두 routes.py 파일에서 수정 가능)

3. 수정할 내용
- (1)
- Researcher가 선택한 데이터를, Provider의 SFTP에서 Consumer의 SFTP로 넘기기 전 credential (암호화) 과정
- 암호화에 필요한 함수를 외부 모듈로 생성하고자 함 (security.py 내에)
- 하지만 외부 모듈로 불리한 후 routes.py 에서 import 하니 오류 발생
- 원인 파악X -> 일단 routes.py 파일 내에 함수를 입력함
- (2)
- 로그인이나 초대장 수락 등을 실패했을 경우 alert() 뜨도록 코드를 추가했지만, 아무런 변화X
- 원인 파악X