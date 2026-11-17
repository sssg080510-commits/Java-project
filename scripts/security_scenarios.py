#!/usr/bin/env python3
"""Bounded, local-only security scenarios for the CookieTrace website; standard library only."""
import argparse
import concurrent.futures
import http.cookiejar
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='http://127.0.0.1:8080')
args = parser.parse_args()
url = urllib.parse.urlsplit(args.url)
if url.hostname != '127.0.0.1' or url.scheme != 'http' or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
    parser.error('Use http://127.0.0.1:<port>; these scenarios run only against the local lab.')
base = args.url.rstrip('/')

class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ''

    def call(self, path, method='GET', fields=None, ua='CookieTrace-Test-Browser', location=None, csrf=True):
        headers = {'User-Agent': ua}
        if csrf:
            headers['X-CSRF-Token'] = self.csrf
        if location:
            headers['X-Lab-Location'] = location
        body = urllib.parse.urlencode(fields or {}).encode() if method == 'POST' else None
        req = urllib.request.Request(base + path, body, headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as response:
                return response.status, json.load(response), response.headers
        except urllib.error.HTTPError as error:
            return error.code, json.load(error), error.headers

    def signin(self, fields, register=True):
        status, _, headers = self.call('/api/register' if register else '/api/login', 'POST', fields)
        assert status == 200, ('authentication', status)
        cookie = headers.get('Set-Cookie', '')
        assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
        status, me, _ = self.call('/api/me')
        assert status == 200
        self.csrf = me['csrf']
        return me

    def report(self):
        status, data, _ = self.call('/api/dashboard')
        assert status == 200
        return data


def signals(data):
    return {a['analyzer'] for s in data['sessions'] for a in s['alerts']}

client = Client()
credentials = {'username': 'test_' + secrets.token_hex(5), 'password': secrets.token_urlsafe(20)}
me = client.signin(credentials)
assert client.call('/api/activity', 'POST')[0] == 200
baseline = signals(client.report())
assert not baseline.intersection({'UserAgentAnalyzer', 'IpChangeAnalyzer', 'ConcurrentSessionAnalyzer', 'ImpossibleTravelAnalyzer', 'BurstAnalyzer'})
assert client.call('/api/activity', 'POST', csrf=False)[0] == 403
assert Client().call('/api/dashboard')[0] == 401
print('PASS: normal traffic, cookie flags, CSRF rejection, anonymous access rejection')

# Copy only our own dedicated test account cookie; no cookie discovery or theft.
replay = Client()
for cookie in client.jar:
    replay.jar.set_cookie(cookie)
status, replay_me, _ = replay.call('/api/me', ua='CookieTrace-Test-Replay')
assert status == 200
replay.csrf = replay_me['csrf']
assert replay.call('/api/activity', 'POST', ua='CookieTrace-Test-Replay')[0] == 200
assert 'UserAgentAnalyzer' in signals(client.report())
print('PASS: test cookie replay with changed browser identity detected')

if me['lab']:
    assert client.call('/api/activity', 'POST', location='chennai')[0] == 200
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(c.call, '/api/activity', 'POST', location=loc)
                   for c, loc in ((client, 'chennai'), (replay, 'london'))]
        assert all(f.result()[0] == 200 for f in futures)
    data = client.report()
    assert {'IpChangeAnalyzer', 'ConcurrentSessionAnalyzer', 'ImpossibleTravelAnalyzer'} <= signals(data)
    assert any(e['simulated'] for e in data['timeline'])
    assert any(s['level'] == 'HIGH' for s in data['sessions'])
    print('PASS: labelled location fixtures trigger IP change, concurrent usage, impossible travel, HIGH risk')
else:
    assert client.call('/api/activity', 'POST', location='london')[0] == 200
    data = client.report()
    assert not any(e['simulated'] for e in data['timeline'])
    assert 'ImpossibleTravelAnalyzer' not in signals(data)
    print('PASS: normal mode ignores lab location headers')

for _ in range(20):
    assert client.call('/api/activity', 'POST')[0] == 200
assert 'BurstAnalyzer' in signals(client.report())
print('PASS: bounded request burst detected')

other = Client()
other.signin({'username': 'test_' + secrets.token_hex(5), 'password': secrets.token_urlsafe(20)})
assert not ({s['id'] for s in other.report()['sessions']} & {s['id'] for s in client.report()['sessions']})
assert other.report()['events'] == 1
print('PASS: another account cannot see the test account sessions or events')

assert client.call('/api/logout', 'POST')[0] == 200
assert replay.call('/api/activity', 'POST')[0] == 401
assert client.call('/api/dashboard')[0] == 401
client.signin(credentials, register=False)
assert len(client.report()['sessions']) == 2
print('PASS: logout invalidates replayed cookie; fresh login preserves event history')
print('All scenarios passed. Test accounts and hashed event records remain in the configured database.')
