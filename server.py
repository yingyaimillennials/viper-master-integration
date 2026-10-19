"""Generation-only ASGI gateway. Run with Uvicorn; no generated code execution."""
import argparse,ast,asyncio,hashlib,hmac,json,logging,os,re,sqlite3,time,uuid
from contextlib import closing
from pathlib import Path
from dataclasses import dataclass
import httpx
LOG=logging.getLogger('guardian')
ZERO='0'*64
class DependencyError(RuntimeError):pass
class IntegrityError(RuntimeError):pass

def encode(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def sha(x):return hashlib.sha256(x.encode()).hexdigest()
def unique(items):
    d={}
    for k,v in items:
        if k in d:raise ValueError('duplicate key')
        d[k]=v
    return d
def constant(v):raise ValueError('JSON constant')
def decode(b):return json.loads(b.decode('utf-8'),object_pairs_hook=unique,parse_constant=constant)

class Ledger:
    def __init__(self,path):
        self.path=Path(path).resolve()
        if not self.path.is_file():raise IntegrityError('ledger missing')
        self.verify()
    @classmethod
    def initialize(cls,path):
        p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb'):pass
        with closing(sqlite3.connect(p,isolation_level=None)) as c:
            c.execute('PRAGMA synchronous=FULL');c.execute('BEGIN IMMEDIATE')
            c.execute('CREATE TABLE ledger(seq INTEGER PRIMARY KEY,payload TEXT NOT NULL,hash TEXT NOT NULL)')
            x={'seq':0,'ts_ns':0,'event':'genesis','request_id':'GENESIS','subject':'system','prompt_sha256':ZERO,'code_sha256':None,'previous_hash':ZERO}
            c.execute('INSERT INTO ledger VALUES(?,?,?)',(0,encode(x),sha(encode(x))));c.execute('COMMIT')
        return cls(p)
    def connect(self):
        c=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=2)
        try:c.execute('PRAGMA synchronous=FULL');return c
        except Exception:c.close();raise
    def checked(self,c):
        rows=c.execute('SELECT seq,payload,hash FROM ledger ORDER BY seq').fetchall()
        if not rows:raise IntegrityError('empty chain')
        prev=ZERO
        for i,(seq,raw,h) in enumerate(rows):
            p=decode(raw.encode())
            if not isinstance(p,dict) or set(p)!={'seq','ts_ns','event','request_id','subject','prompt_sha256','code_sha256','previous_hash'}:raise IntegrityError('fields')
            if type(p['seq']) is not int or type(p['ts_ns']) is not int or p['ts_ns']<0:raise IntegrityError('types')
            for k in ['event','request_id','subject','prompt_sha256','previous_hash']:
                if not isinstance(p[k],str):raise IntegrityError('text')
            for digest in [p['prompt_sha256'],p['previous_hash'],h]+([] if p['code_sha256'] is None else [p['code_sha256']]):
                if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise IntegrityError('digest')
            if seq!=i or p['seq']!=i or p['previous_hash']!=prev or encode(p)!=raw or sha(raw)!=h:raise IntegrityError('chain')
            if i==0 and p!={'seq':0,'ts_ns':0,'event':'genesis','request_id':'GENESIS','subject':'system','prompt_sha256':ZERO,'code_sha256':None,'previous_hash':ZERO}:raise IntegrityError('genesis')
            prev=h
        return len(rows),prev
    def verify(self):
        with closing(self.connect()) as c:
            c.execute('BEGIN')
            try:return self.checked(c)
            finally:c.execute('ROLLBACK')
    def record(self,event,rid,subject,prompt_digest,code_digest=None):
        with closing(self.connect()) as c:
            try:
                c.execute('BEGIN IMMEDIATE');seq,prev=self.checked(c)
                p={'seq':seq,'ts_ns':time.time_ns(),'event':event,'request_id':rid,'subject':subject,'prompt_sha256':prompt_digest,'code_sha256':code_digest,'previous_hash':prev}
                h=sha(encode(p));c.execute('INSERT INTO ledger VALUES(?,?,?)',(seq,encode(p),h));c.execute('COMMIT');return {'seq':seq,'entry_hash':h}
            except Exception:
                if c.in_transaction:
                    try:c.execute('ROLLBACK')
                    except sqlite3.Error:pass
                raise

@dataclass(frozen=True)
class Settings:
    db:str='/data/ledger.sqlite3'
    registry:str='/app/config/api_keys.json'
    opa_url:str='http://opa:8181/v1/data/sovereign/allow'
    ollama_url:str='http://ollama:11434'
    model:str=''
    max_active:int=2
    max_readers:int=8
    body_deadline:float=5.0
    generation_deadline:float=120
    def __post_init__(self):
        from urllib.parse import urlsplit
        if not self.model or type(self.max_active) is not int or self.max_active<1 or not 0<self.generation_deadline<=600:raise ValueError('settings')
        if type(self.max_readers) is not int or self.max_readers<1 or self.max_readers>1000:raise ValueError('max_readers')
        if not (0<self.body_deadline<=60):raise ValueError('body_deadline')
        for url in [self.opa_url,self.ollama_url]:
            u=urlsplit(url)
            if u.scheme not in {'http','https'} or not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment:raise ValueError('endpoint')
    @classmethod
    def from_env(cls):
        def _int(k,d):
            v=os.environ.get(k)
            return int(v) if v is not None else d
        def _float(k,d):
            v=os.environ.get(k)
            return float(v) if v is not None else d
        return cls(
            db=os.environ.get('LEDGER_DB','/data/ledger.sqlite3'),
            registry=os.environ.get('REGISTRY_PATH','/app/config/api_keys.json'),
            opa_url=os.environ.get('OPA_URL','http://opa:8181/v1/data/sovereign/allow'),
            ollama_url=os.environ.get('OLLAMA_URL','http://ollama:11434'),
            model=os.environ.get('OLLAMA_MODEL',''),
            max_active=_int('MAX_ACTIVE',2),
            max_readers=_int('MAX_READERS',8),
            body_deadline=_float('BODY_DEADLINE',5.0),
            generation_deadline=_float('GENERATION_DEADLINE',120.0),
        )

def registry_entries(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size>65536:raise DependencyError('registry')
    d=decode(p.read_bytes())
    if not isinstance(d,dict) or set(d)!={'keys'} or not isinstance(d['keys'],list) or len(d['keys'])>1000:raise DependencyError('registry format')
    seen=set();out=[]
    for e in d['keys']:
        if not isinstance(e,dict) or set(e)!={'key_sha256','subject','role','enabled'}:raise DependencyError('key entry')
        if not isinstance(e['key_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',e['key_sha256']) or e['key_sha256'] in seen:raise DependencyError('key digest')
        if e['role'] not in {'developer','admin'} or type(e['enabled']) is not bool or not isinstance(e['subject'],str) or not re.fullmatch('[A-Za-z0-9_-]{1,80}',e['subject']):raise DependencyError('key scope')
        seen.add(e['key_sha256']);out.append(e)
    return out

def code_valid(code):
    if not isinstance(code,str) or not code.strip() or len(code.encode())>131072:return False
    try:t=ast.parse(code)
    except (SyntaxError,ValueError,RecursionError):return False
    if not t.body:return False
    for n in ast.walk(t):
        if isinstance(n,(ast.Import,ast.ImportFrom)):return False
        if isinstance(n,ast.Name) and n.id in {'exec','eval','open','compile','__import__','getattr','globals','locals','input','breakpoint'}:return False
        if isinstance(n,ast.Attribute) and n.attr.startswith('__'):return False
    return True

class Gateway:
    def __init__(self,settings=None,transport=None):
        self.settings=settings;self.transport=transport;self.client=None;self.ledger=None
        self.active=0
        self.readers=0
    async def start(self):
        self.settings=self.settings or Settings.from_env()
        registry_entries(self.settings.registry)
        self.ledger=await asyncio.to_thread(Ledger,self.settings.db)
        self.client=httpx.AsyncClient(transport=self.transport,follow_redirects=False,trust_env=False,timeout=httpx.Timeout(15,connect=3),limits=httpx.Limits(max_connections=8,max_keepalive_connections=4))
    async def stop(self):
        if self.client:await self.client.aclose()
    async def upstream(self,method,url,payload=None,limit=1048576):
        async with self.client.stream(method,url,json=payload,headers={'Accept':'application/json'}) as r:
            if r.status_code!=200 or r.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':raise DependencyError('upstream contract')
            b=bytearray()
            async for chunk in r.aiter_bytes():
                if len(b)+len(chunk)>limit:raise DependencyError('upstream size')
                b.extend(chunk)
            d=decode(bytes(b))
            if not isinstance(d,dict):raise DependencyError('upstream envelope')
            return d
    async def event(self,event,rid,sub,pd,cd=None):return await asyncio.to_thread(self.ledger.record,event,rid,sub,pd,cd)
    async def dispatch(self,scope,receive):
        rid=str(uuid.uuid4());path=scope.get('path');method=scope.get('method')
        if method=='GET' and path=='/healthz':return 200,{'status':'alive'},rid
        if self.client is None:return 503,{'error':'NOT_INITIALIZED'},rid
        if method=='GET' and path=='/readyz':
            try:
                async with asyncio.timeout(5):
                    entries=await asyncio.to_thread(registry_entries,self.settings.registry)
                    if not any(e['enabled'] for e in entries):raise DependencyError('no active key')
                    await asyncio.to_thread(self.ledger.verify)
                    d=await self.upstream('POST',self.settings.opa_url,{'input':{'action':'code.generate','prompt':'readiness probe','role':'developer'}},65536)
                    if d.get('result') is not True:raise DependencyError('policy readiness')
                    tags=await self.upstream('GET',self.settings.ollama_url.rstrip('/')+'/api/tags')
                    models=tags.get('models')
                    if not isinstance(models,list) or not any(isinstance(m,dict) and m.get('name')==self.settings.model for m in models):raise DependencyError('model missing')
                return 200,{'status':'ready'},rid
            except Exception:return 503,{'error':'NOT_READY'},rid
        if path!='/v1/generations':return 404,{'error':'NOT_FOUND'},rid
        if method!='POST':return 405,{'error':'METHOD_NOT_ALLOWED'},rid
        headers={}
        for k,v in scope.get('headers',[]):headers.setdefault(k.lower(),[]).append(v)
        auth=headers.get(b'authorization',[])
        if len(auth)!=1:return 401,{'error':'UNAUTHORIZED'},rid
        try:
            raw=auth[0].decode('ascii')
            if not raw.startswith('Bearer '):raise ValueError()
            token=raw[7:]
            if not 32<=len(token)<=512 or not re.fullmatch('[A-Za-z0-9_-]+',token):raise ValueError()
            entries=await asyncio.to_thread(registry_entries,self.settings.registry)
            principal=None;h=sha(token)
            for e in entries:
                if hmac.compare_digest(h,e['key_sha256']) and e['enabled']:principal=e
            if principal is None:return 401,{'error':'UNAUTHORIZED'},rid
        except (ValueError,UnicodeError):return 401,{'error':'UNAUTHORIZED'},rid
        except Exception:return 503,{'error':'AUTH_SERVICE_UNAVAILABLE'},rid
        
        if self.readers>=self.settings.max_readers:return 503,{'error':'READER_BUSY'},rid
        self.readers+=1
        try:
            ct=headers.get(b'content-type',[])
            if len(ct)!=1 or ct[0].split(b';')[0].strip().lower()!=b'application/json':return 415,{'error':'JSON_REQUIRED'},rid
            if len(headers.get(b'content-length',[]))>1:return 400,{'error':'INVALID_CONTENT_LENGTH'},rid
            if b'content-length' in headers:
                try:length=int(headers[b'content-length'][0])
                except ValueError:return 400,{'error':'INVALID_CONTENT_LENGTH'},rid
                if length<0:return 400,{'error':'INVALID_CONTENT_LENGTH'},rid
                if length>65536:return 413,{'error':'BODY_TOO_LARGE'},rid
            body=bytearray()
            try:
                async with asyncio.timeout(self.settings.body_deadline):
                    while True:
                        m=await receive()
                        if m['type']=='http.disconnect':return 400,{'error':'DISCONNECTED'},rid
                        if m['type']!='http.request':return 400,{'error':'INVALID_REQUEST'},rid
                        chunk=m.get('body',b'')
                        if len(body)+len(chunk)>65536:return 413,{'error':'BODY_TOO_LARGE'},rid
                        body.extend(chunk)
                        if not m.get('more_body',False):break
            except TimeoutError:return 408,{'error':'BODY_TIMEOUT'},rid
            try:
                data=decode(bytes(body))
                if not isinstance(data,dict) or set(data)-{'action','prompt','role'} or data.get('action')!='code.generate':raise ValueError()
                prompt=data.get('prompt')
                if not isinstance(prompt,str) or not prompt.strip() or len(prompt)>4096:raise ValueError()
            except Exception:return 422,{'error':'INVALID_PAYLOAD'},rid
        finally:
            self.readers-=1

        if self.active>=self.settings.max_active:return 503,{'error':'BUSY'},rid
        self.active+=1
        try:
            sub=principal['subject'];pd=sha(prompt)
            try:await self.event('request_received',rid,sub,pd)
            except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
            try:
                async with asyncio.timeout(5):
                    d=await self.upstream('POST',self.settings.opa_url,{'input':{'action':'code.generate','prompt':prompt,'role':principal['role']}},65536)
                if type(d.get('result')) is not bool:raise DependencyError('nonboolean')
            except Exception:
                try:await self.event('opa_unavailable',rid,sub,pd)
                except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
                return 503,{'error':'AUTHORIZATION_UNAVAILABLE'},rid
            if d['result'] is False:
                try:await self.event('authz_denied',rid,sub,pd)
                except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
                return 403,{'error':'FORBIDDEN'},rid
            try:await self.event('authz_granted',rid,sub,pd)
            except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
            try:
                async with asyncio.timeout(self.settings.generation_deadline):
                    d=await self.upstream('POST',self.settings.ollama_url.rstrip('/')+'/api/generate',{'model':self.settings.model,'prompt':prompt,'stream':False,'options':{'num_predict':2048}})
                code=d.get('response')
                if d.get('done') is not True or d.get('done_reason')!='stop' or not code_valid(code):raise DependencyError('output invalid')
            except Exception:
                try:await self.event('generation_failed',rid,sub,pd)
                except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
                return 502,{'error':'GENERATION_FAILED'},rid
            try:receipt=await self.event('generated',rid,sub,pd,sha(code))
            except Exception:return 503,{'error':'AUDIT_UNAVAILABLE'},rid
            return 200,{'status':'GENERATED_NOT_EXECUTED','request_id':rid,'code':code,'code_sha256':sha(code),'receipt':receipt},rid
        finally:self.active-=1
    async def __call__(self,scope,receive,send):
        if scope['type']=='lifespan':
            while True:
                m=await receive()
                if m['type']=='lifespan.startup':
                    try:await self.start();await send({'type':'lifespan.startup.complete'})
                    except Exception:await send({'type':'lifespan.startup.failed','message':'configuration or ledger unavailable'});return
                elif m['type']=='lifespan.shutdown':await self.stop();await send({'type':'lifespan.shutdown.complete'});return
            return
        if scope['type']!='http':return
        try:status,data,rid=await self.dispatch(scope,receive)
        except Exception:status,data,rid=503,{'error':'SERVICE_UNAVAILABLE'},str(uuid.uuid4())
        LOG.warning(encode({'event':'http_result','request_id':rid,'status':status}))
        body=encode(data).encode()
        await send({'type':'http.response.start','status':status,'headers':[(b'content-type',b'application/json; charset=utf-8'),(b'content-length',str(len(body)).encode()),(b'cache-control',b'no-store'),(b'x-content-type-options',b'nosniff'),(b'x-request-id',rid.encode())]})
        await send({'type':'http.response.body','body':body})
app=Gateway()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--init-ledger',action='store_true');p.add_argument('--db',default=os.environ.get('LEDGER_DB','/data/ledger.sqlite3'));a=p.parse_args()
    if not a.init_ledger:p.error('use uvicorn server:app for HTTP mode')
    Ledger.initialize(a.db);print('INITIALIZED')
