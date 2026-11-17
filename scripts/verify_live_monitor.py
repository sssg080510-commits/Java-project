import os, subprocess, tempfile, time, urllib.request, urllib.error, urllib.parse, http.cookiejar, json
with tempfile.TemporaryDirectory(prefix='ct-monitor-') as directory:
    port='18082'
    env=dict(os.environ,COOKIETRACE_LAB='true',COOKIETRACE_ADMIN='monitor',PORT=port,COOKIETRACE_DB=directory+'/test.db')
    server=subprocess.Popen(['java','-cp','target/classes:target/dependency/*','com.cookietrace.web.WebServer'],env=env)
    base='http://127.0.0.1:'+port
    def client(): return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(op,path,body=None,csrf=''):
        req=urllib.request.Request(base+path,data=urllib.parse.urlencode(body).encode() if body is not None else None,headers={'X-CSRF-Token':csrf})
        try:
            with op.open(req,timeout=10) as r: return r.status,json.load(r)
        except urllib.error.HTTPError as e: return e.code,json.load(e)
    try:
        admin=client()
        for _ in range(60):
            try:
                if call(admin,'/health')[0]==200: break
            except OSError: time.sleep(.1)
        assert call(admin,'/api/register',{'username':'monitor','password':'long-test-password'})[0]==200
        _,me=call(admin,'/api/me'); assert me['admin']
        assert call(admin,'/api/dashboard')[1]['scope']=='website'
        visitor=client()
        assert call(visitor,'/api/register',{'username':'visitor','password':'long-test-password'})[0]==200
        _,v=call(visitor,'/api/me'); assert not v['admin']
        assert call(visitor,'/api/demo',{},v['csrf'])[0]==403
        before=call(visitor,'/api/dashboard')[1]['events']
        assert call(visitor,'/api/profile')[0]==200
        after=call(visitor,'/api/dashboard')[1]
        assert after['events']==before+1
        assert {s['user'] for s in after['sessions']}=={'visitor'}
        assert {'monitor','visitor'} <= {s['user'] for s in call(admin,'/api/dashboard')[1]['sessions']}
        print('PASS: automatic protected-request capture; website-wide admin view; ordinary account isolation; demo access control',flush=True)
        assert call(admin,'/api/demo',{},me['csrf'])[0]==202
        for _ in range(35):
            _,data=call(admin,'/api/dashboard')
            if data['scenario'].startswith('Complete'): break
            time.sleep(.5)
        else: raise AssertionError(data['scenario'])
        lab=[s for s in data['sessions'] if s['user'].startswith('lab_')]
        assert len(lab)==1 and lab[0]['level']=='HIGH'
        signals={a['analyzer'] for a in lab[0]['alerts']}
        assert {'UserAgentAnalyzer','IpChangeAnalyzer','ConcurrentSessionAnalyzer','ImpossibleTravelAnalyzer','BurstAnalyzer'}<=signals
        assert any(e['path']=='/api/profile' and e['simulated'] for e in data['timeline'])
        for path in ['/','/shop','/app.js','/shop.js','/style.css']:
            with admin.open(base+path) as r: assert r.status==200 and len(r.read())>100
        print('PASS: one-click scenario sends real HTTP traffic; monitor automatically flags HIGH risk with all five detectors; website assets served',flush=True)
    finally:
        server.terminate();server.wait(timeout=10)
