# py_ver == "3.6.9"
import flask 


app = flask.Flask(__name__)


import requests
# check internet connection is available
inet_conn = False
if requests.__version__ <= '2.19.1':
    try:
        requests.get('https://google.com')
        inet_conn = True
    except:
        pass


@app.route('/introduction')
def introduction():
    return """
            <html>
                <title>Знакомство</title>
                <body>
                    <form action="/set_name">
                        Представьтесь, пожалуйста: <input name="name" type="text" />
                        <input name="submit" type="submit">
                    </form>
                </body>
            </html>
"""


@app.route('/')
def index_page_name():
    if flask.request.cookies.get('name'):
        return """
            <html>
                <title>Приветствие</title>
                <body>
                     <h1>Привет, %s!</h1>
                </body>
            </html>
""" %escape(flask.request.cookies.get('name'))
    else:
        return """
            <html>
                <title>Приветствие</title>
                <script></script>
                <body>
                    <a href="/introduction">Как вас зовут?</a>
                </body>
            </html>
"""


@app.route('/set_name')
def cookie_setter():
    response = flask.make_response(flask.redirect('/'))
    if flask.request.args.get('name'):
        response.set_cookie('name', flask.request.args.get('name'), max_age = 60*60*24*7)
    return response


import os
from db import get_connection


def authenticate(name, password):


    sql_statement = "SELECT * FROM users WHERE name = ? AND password = ?;"


    cursor = get_connection(
                            os.environ['DB_LOGIN'],
                            os.environ['DB_PASSWORD']
                            ).cursor()
    result = cursor.execute(sql_statement, (name, password)).fetchone()
    cursor.close()
    return result


@app.route('/login')
def index_page():
    return """
            <html>
                <title>Login page</title>
                <body>
                    <form action="/auth" method="post">
                        Login: <input name="name" type="text"/>
                        Password: <input name="password" type="password" />
                        <input name="submit" type="submit" value="Log in">
                        <input name="redirect_url" value="/?logged_in=1" type="hidden" />
                    </form>
                </body>
            </html>
        """


import hmac, hashlib, datetime
from datetime import date


@app.route('/auth', methods=["GET", "POST"])
def login_page():
    name = flask.request.form.get('name')
    password = flask.request.form.get('password')

    if name == None or password == None:
        return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """
    hmac_msg = name + password + "SALT_123nwjdnf023" + datetime.datetime.today().strftime("%Y/%m/%d")
    
    hmac_inst = hmac.new(os.environ['SIGNATURE_KEY'].encode('utf8'),
                         msg=hmac_msg.encode('utf8'),
                         digestmod='sha256')
    already_auth = flask.request.cookies.get('ssid') == hmac_inst.hexdigest()
    just_auth = authenticate(name, password)

    if already_auth or just_auth:
        redirect_url = flask.request.args.get('redirect_url', '/')
        with open("urldoc.txt", "r") as urls_dict:
            for line in urls_dict:
                url_allowed = line.strip()  
                if redirect_url == url_allowed:
                    response = flask.make_response(flask.redirect(redirect_url))
                    if just_auth:
                        response.set_cookie('ssid', hmac_inst.hexdigest(), max_age = 60*60*24*7)
                    return response
        return """
            <html>
                <body>
                    Successfully loged in
                </body>
            </html>                    
        """ 

    return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
