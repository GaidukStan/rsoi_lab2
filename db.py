from pathlib import Path
from pydblite import Base

if not Path('db').exists():
    Path('db').mkdir()

"""
Base for client's application on service via client_id
"""
client_base = Base('db/client_base.pdl')
if client_base.exists():
    client_base.open()
else:
    client_base.create('secret', 'redirect_uri', 'name')
"""
Base for keeping authorization codes while oauth
"""
authorization_code = Base('db/authorization_code.pdl')
if authorization_code.exists():
    authorization_code.open()
else:
    authorization_code.create('user_id', 'code', 'expire_time')
"""
Base for access_tokens for authorized users
"""
access_token = Base('db/access_token.pdl')
if access_token.exists():
    access_token.open()
else:
    access_token.create('user_id', 'access', 'expire_time', 'refresh')
"""
Base of users for registration and logining in
"""
user_base = Base('db/user_base.pdl')
if user_base.exists():
    user_base.open()
else:
    user_base.create('login', 'pswd', 'name', 'email')
"""
Base - list of available races for participating
"""
races_base = Base('db/races_base.pdl')
if races_base.exists():
    races_base.open()
else:
    races_base.create('id','name','country','distance','laps')
"""
Base for users request to participate certain races
"""
entrylist = Base('db/entrylist.pdl')
if entrylist.exists():
    entrylist.open()
else:
    entrylist.create('user_id','name','rclass')

