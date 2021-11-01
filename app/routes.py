from app import app
from flask import render_template, redirect, url_for, session, request, Response
import paramiko
import os.path

# 로그인 정보
root_email, root_password = "asd@asd.com", "asd"


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

@app.route('/researcher-irb/accpet-invitation', methods=['POST'])
def researcher_irb_accept_invitation() :
    values = request.get_json(force=True)
    session['IRB_inv'] = values
    return 'Researcher accepts IRB invitation'





@app.route('/provider')
@app.route('/provider/invitation')
def provider_invitation() :
    return render_template('provider_invitation.html')

@app.route('/provider/data')
def provider_data() :
    return render_template('provider_data.html')