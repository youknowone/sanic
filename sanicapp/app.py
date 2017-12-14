import asyncio
from sanic import Sanic
from sanic.response import json

from sanic import Blueprint
bp = Blueprint('test')


app = Sanic()
app.config.REQUEST_TIMEOUT = 0.1


@app.route('/')
async def test(request):
    while True:
        await asyncio.sleep(0.3)
        print('not dead')
    return json({'lock': request['lock']})


lock = False


app.blueprint(bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)