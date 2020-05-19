# py_ver == "3.6.9"
import flask


app = flask.Flask(__name__)

import time
import logging


logging.basicConfig(filename="/var/log/secnotify/secnotify.log",
                    level=logging.DEBUG,
                    format='%(asctime)s:%(module)s:%(name)s:%(levelname)s:%(message)s')
logging.debug("secnotify startup")
logger = logging.getLogger()


@app.after_request
def after_request(response):
    timestamp = time.strftime('[%Y-%b-%d %H:%M]')
    app.logger.error(
                     '%s %s %s %s %s %s %s %s',
                                               timestamp,
                                               flask.request.remote_addr,
                                               flask.request.method,
                                               flask.request.full_path,
                                               flask.request.cookies,
                                               flask.request.data,
                                               response.status,
                                               response.data
                    )
    return response


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
def index_page():
    if flask.request.cookies.get('name'):
        return """
            <html>
                <title>Приветствие</title>
                <script>
window.getCookie = function(name) {
  var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  if (match) return match[2];
}
document.write('<h1>Привет, ' + escape(getCookie('name')) + '!</h1>')
                </script>
                <body>

                </body>
            </html>
"""
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
    maxage = 60*60*24
    response = flask.make_response(flask.redirect('/'))
    response.set_cookie('name', flask.request.args.get('name'),maxage,secure=True,httponly=True,samesite='Strict')
    return response


import yaml, base64, hashlib


@app.route('/secret')
def get_msg():
    if flask.request.method == 'POST':
        if flask.request.data:
            msg = yaml.safe_load(base64.b64decode(flask.request.data))
            if msg.hash == hashlib.sha256(msg.text.encode('utf8')).hexdigest():
                with open('messages', 'a') as msg_log:
                    msg_log.write(msg.text)


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
