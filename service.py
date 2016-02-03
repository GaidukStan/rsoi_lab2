from flask import Flask, request, redirect, render_template, url_for 
import json
from hashlib import sha256
import db
from uuid import uuid4
from datetime import datetime, timedelta
import json
import math

base_url = r"127.0.0.1:5000"



application = Flask(__name__)

@application.route('/', methods=['GET'])
def index():    
    print ('in /')
    return redirect(url_for('send_registration_form'))

"""
GET user the registration form
"""
@application.route('/registration', methods=['GET'])
def send_registration_form():
    print ('in /registration-get')
    return render_template("register.html")
"""
try to POST info about user to service
"""
@application.route('/registration',methods=['POST'])
def register_user():
    print ('in /registration-post')
    ##############
    login = request.form['login']
    
    if not login:
        return render_template('register_failed.html', reason='Empty login not allowed.')

    password = request.form['password']
    name = request.form['name'] or None
    email = request.form['email'] or None

    print (login, ' ', name, ' ',password, ' ',email)

    if db.user_base(login=login):
        return render_template('register_failed.html', reason='User already exists.'.format(login))

    db.user_base.insert(login=login,
                   pswd=sha256(password.encode('UTF-8')).digest(),
                   name=name,
                   email=email)
    db.user_base.commit()

    return render_template('register_successed.html', login=request.form['login'])

@application.route('/oauth/authorize',methods=['GET'])
def get_authorize_form():
    response_type = request.args.get('response_type', None)
    client_id = request.args.get('client_id', None)
    state = request.args.get('state', None)

    print (response_type,' ', client_id)

    if client_id is None:
        return render_template('authorization_failed.html', reason='Require client_id.')
    try:
        client_id = int(client_id)
    except:
        client_id = None
    id=client_id    
    if id not in db.client_base:
            return render_template('authorization_failed.html', reason='client_id is invalid.')

    if response_type is None:
        return redirect(db.client_base[client_id]['redirect_uri'] + '?error=invalid_request' +
                                                              ('' if state is None else '&state=' + state), code=302)
    if response_type != 'code':
        return redirect(db.client_base[client_id]['redirect_uri'] + '?error=unsupported_response_type' +
                                                              ('' if state is None else '&state=' + state), code=302)

    return render_template('authorization.html', state=state,
                                                  client_id=client_id,
                                                  client_name=db.client_base[client_id]['name'])






@application.route('/oauth/authorize',methods=['POST'])
def authorize_user():
    client_id = int(request.form.get('client_id'))
    login = request.form.get('login')
    password = request.form.get('password')
    state = request.form.get('state', None)

    if not db.user_base(login=login):
        return redirect(db.client_base[client_id]['redirect_uri'] + '?error=access_denied' + ('' if state is None else '&state=' + state), code=302)
    if db.user_base(login=login)[0]['pswd'] != sha256(password.encode('UTF-8')).digest():
        return redirect(db.client_base[client_id]['redirect_uri'] + '?error=access_denied' + ('' if state is None else '&state=' + state), code=302)

    code=sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    db.authorization_code.insert(user_id=db.user_base(login=login)[0]['__id__'],
                                 code=code,
                                 expire_time=datetime.now() + timedelta(minutes=30))
    db.authorization_code.commit()

    return redirect(db.client_base[client_id]['redirect_uri'] + '?code=' + code + ('' if state is None else '&state=' + state), code=302)
"""
position for authorixation redirect to get code
"""
@application.route('/red',methods=['GET'])
def get_code():
    
    code = request.args.get('code')
    if code is None:
        return "empty_code"
    else:
        url = "http:localhost:5000/oauth/token?code="+ code +"&grant_type=authorization_code&client_id=0&client_secret=2815F7D30CED0010092C0C5DCBE1366C1CD4CFF48E63CD7A8A8CC577088ED47C22CD5184899748BE33BF32291AE415FE83AC547726B44E4"
        return code

@application.route('/oauth/token', methods=['POST'])
def token():
    try:
        grant_type = request.form.get('grant_type')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    except KeyError:
        return json.dumps({'error': 'invalid_request'}), 400, {
            'Content-Type': 'application/json;charset=UTF-8',        
        }

    try:
        client_id = int(client_id)
    except:
        client_id = None
    if client_id not in db.client_base or db.client_base[client_id]['secret'] != client_secret:
        return json.dumps({'error': 'invalid_client'}), 400, {
            'Content-Type': 'application/json;charset=UTF-8',        
        }

    if grant_type == 'authorization_code':
        try:
            code = request.form.get('code')
        except KeyError:
            return json.dumps({'error': 'invalid_request'}), 400, {
                'Content-Type': 'application/json;charset=UTF-8',        
            }

        if not db.authorization_code(code=code) or db.authorization_code(code=code)[0]['expire_time'] < datetime.now():
            return json.dumps({'error': 'invalid_grant'}), 400, {
                'Content-Type': 'application/json;charset=UTF-8',        
            }

        user_id = db.authorization_code(code=code)[0]['user_id']

        db.authorization_code.delete(db.authorization_code(code=code))
        db.authorization_code.commit()
    elif grant_type == 'refresh_token':
        try:
            refresh_token = request.form.get('refresh_token')
        except KeyError:
            return json.dumps({'error': 'invalid_request'}), 400, {
                'Content-Type': 'application/json;charset=UTF-8',        
            }

        if not db.access_token(refresh=refresh_token):
            return json.dumps({'error': 'invalid_grant'}), 400, {
                'Content-Type': 'application/json;charset=UTF-8',        
            }

        user_id = db.access_token(refresh=refresh_token)[0]['user_id']

        db.access_token.delete(db.access_token(refresh=refresh_token))
        db.access_token.commit()
    else:
        return json.dumps({'error': 'unsupported_grant_type'}), 400, {
            'Content-Type': 'application/json;charset=UTF-8',        
        }

    access_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    expire_time = datetime.now() + timedelta(hours=1)
    refresh_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    db.access_token.insert(user_id=user_id,
                    access=access_token,
                    expire_time=expire_time,
                    refresh=refresh_token)
    db.access_token.commit()

    return json.dumps({
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': 3600,
        'refresh_token': refresh_token,
    }), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    }

@application.route('/races/', methods=['GET'])
def get_races():
    try:
        per_page = int(request.args.get('per_page', 5))
        if per_page < 1 or per_page > 100:
            raise Exception()
        page = int(request.args.get('page', 0))
        if page < 0 or page > len(db.races_base) // per_page:
            raise Exception()
    except:
        return '', 400

    items = []
    for i, races_base in enumerate(db.races_base):
        if i < page * per_page:
            continue
        if i >= (page + 1) * per_page:
            break
        items.append({
            'id': races_base['__id__'],
            'name': races_base['name'],
            'country': races_base['country'],
            'distance': races_base['distance'],
            'laps': races_base['laps'],
        })

    return json.dumps({
        'items': items,
        'per_page': per_page,
        'page': page,
        'page_count': math.ceil(len(db.races_base) / per_page)
    }, indent=4), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
    }

@application.route('/races/<id>', methods=['GET'])
def get_particular_race(id):
    try:
        id = int(id)
        if id not in db.races_base:
            raise Exception()
    except:
        return '', 404

    races_base = db.races_base[id]
    return json.dumps({
        'id': races_base['__id__'],
        'name': races_base['name'],
        'country': races_base['country'],
        'distance': races_base['distance'],
        'laps': races_base['laps'],
    }, indent=4), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
    }

@application.route('/me', methods=['GET'])
def get_me():

    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    print ('--', access_token)
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 403 

    user_id = db.access_token(access=access_token)[0]['user_id']

    return json.dumps({
        'login': db.user_base[user_id]['login'],
        'name': db.user_base[user_id]['name'],
        'email': db.user_base[user_id]['email'],
    }, indent=4), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
    }


@application.route('/entrylist/', methods=['GET'])
def get_entrylist():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 401 

    user_id = db.access_token(access=access_token)[0]['user_id']
    print (user_id)
    try:
        per_page = int(request.args.get('per_page'))
        print (per_page)
        if per_page < 0 or per_page > 100:
            raise Exception()
        page = int(request.args.get('page'))
        print (page, len(db.entrylist(user_id=user_id))) 
        if page < 0 or page > len(db.entrylist) // per_page:
            raise Exception()
    except:
        return '', 400

    items = []
    for i, entrylist in enumerate(db.entrylist):
        if i < page * per_page:
            continue
        if i >= (page + 1) * per_page:
            break

        if int(entrylist['user_id']) != 0:
            print ('*!=0*')
            continue
        

        items.append({
            'id': entrylist['__id__'],
            'user_id': entrylist['user_id'],
            'name': entrylist['name'],
            'rclass': entrylist['rclass'],
        })

    return json.dumps({
        'items': items,
        'per_page': per_page,
        'page': page,
        'page_count': math.ceil(len(db.entrylist) / per_page)
    }, indent=4), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
    }


@application.route('/entrylist/<id>', methods=['GET'])
def get_particular_entry(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 401

    user_id = db.access_token(access=access_token)[0]['user_id']

    try:
        id = int(id)
        if id not in db.entrylist:
            raise Exception()
    except:
        return '', 404

    entrylist = db.entrylist[id]

    if int(entrylist['user_id']) != user_id:
        return '', 404


    return json.dumps({
        'id': entrylist['__id__'],
        'name': entrylist['name'],
        'rclass': entrylist['rclass'],
    }, indent=4), 200, {
        'Content-Type': 'application/json;charset=UTF-8',        
    }

@application.route('/entrylist/', methods=['POST'])
def post_entry():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 401

    user_id = db.access_token(access=access_token)[0]['user_id']

    try:
        entrylist = request.get_json(force=True)
        

        #for event in entrylist['event']:
            #print (entrylist['event']['id'])
        #if event['id'] not in db.event:
        count = 0
        records = enumerate(db.races_base)
        for rec in records: 
            if rec[1]['name'] != entrylist['name']:
                count = count + 1 

        if count >= len(db.races_base):
            raise Exception()
    except:
        return '', 400

    print (entrylist['rclass'])
    print (entrylist['name'])

    
    id = db.entrylist.insert(user_id=user_id,
                        name=entrylist['name'],
                        rclass=entrylist['rclass'])

    db.entrylist.commit()

    return '', 201, {
        'Location': '/entrylist/{}'.format(id)
    }
    
@application.route('/entrylist/<id>', methods=['DELETE'])
def delete_entry_item(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 401

    user_id = db.access_token(access=access_token)[0]['user_id']

    try:
        id = int(id)
        if id not in db.entrylist or db.entrylist[id]['user_id'] != user_id:
            raise Exception()
    except:
        return '', 404

    db.entrylist.delete(db.entrylist[id])
    db.entrylist.commit()

    return '', 200

@application.route('/entrylist/<id>', methods=['PUT'])
def put_entry_item(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    if not db.access_token(access=access_token) or db.access_token(access=access_token)[0]['expire_time'] < datetime.now():
        return '', 401

    user_id = db.access_token(access=access_token)[0]['user_id']

    try:
        id = int(id)
        print ('id= ', id)
        if id not in db.entrylist: # or db.entrylist[id]['user_id'] != user_id:
            raise Exception()

        records = enumerate(db.entrylist)
        for i, rec in records:
            if (i == id):
                if (int(rec['user_id']) != user_id):
                    raise Exception()
    except:
        return '', 404

    try:
        entrylist = request.get_json(force=True)
        count = 0
        records = enumerate(db.races_base)
        for rec in records: 
            if rec[1]['name'] != entrylist['name']:
                count = count + 1 

        if count >= len(db.races_base):
            raise Exception()
    except:
        return '', 400

    print (entrylist['rclass'])
    print (entrylist['name'])

    
    db.entrylist.update(db.entrylist[id], name=entrylist['name'],
                                  rclass=entrylist['rclass'])

    db.entrylist.commit()
    
    return '', 200

if __name__ == "__main__":
    application.run(port=5000, debug=True)
