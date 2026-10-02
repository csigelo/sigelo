import os
from flask import Flask, request
from sigelo_accept import accept, challenge
app = Flask(__name__)
@app.get('/sigelo/challenge')
def get_challenge(): return challenge(request.args.get('did'), 'example.com')
@app.post('/sigelo/login')  # body: { challenge, did, sig, bundle } — on success put the DID in your session
def login(): b = request.get_json(force=True); return {'did': accept(b['challenge'], b, b['bundle'])['did']}
@app.errorhandler(Exception)
def refuse(e): return {'error': str(e)}, getattr(e, 'code', 401)
if __name__ == '__main__': app.run(port=int(os.environ.get('PORT', 3000)))
