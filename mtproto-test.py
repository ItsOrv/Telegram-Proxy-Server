#!/usr/bin/env python3
_A0='https://core.telegram.org/getProxySecret'
_z='msgs_to_client'
_y='msgs_from_client'
_x='connects'
_w='\r\n\r\n'
_v='Connection: close'
_u='The Telegram server connection is bad: %d (%s %s) %s'
_t=b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03'
_s='seq_no'
_r='block_size'
_q='upstream'
_p='connects_with_duration_le_%s'
_o='decryptor'
_n='encryptor'
_m='www.google.com'
_l='00000000000000000000000000000000'
_k=b'\xdd\xdd\xdd\xdd'
_j=b'\xee\xee\xee\xee'
_i='2001:b28:f23d:f003::d'
_h='2001:67c:04e8:f002::d'
_g='2001:b28:f23d:f001::d'
_f='91.108.56.181'
_e='149.154.162.38'
_d='octets_from_client'
_c='octets_to_client'
_b=b'\x00\x00\x00\x00'
_a='ascii'
_Z='SKIP_SEND'
_Y=b'\x03\x03'
_X=b'\x14'
_W='2001:67c:04e8:f004::d'
_V='149.154.175.100'
_U='149.154.175.50'
_T='user'
_S='SIMPLE_ACK'
_R='curr_connects'
_Q='val'
_P='peername'
_O='QUICKACK_FLAG'
_N=':'
_M='ipv4'
_L=b'\x00'
_K='socket'
_J='tls'
_I='secure'
_H='ipv6'
_G='classic'
_F=b''
_E='big'
_D='little'
_C=None
_B=False
_A=True
import asyncio,socket,urllib.parse,urllib.request,collections,time,datetime,hmac,base64,hashlib,random,binascii,sys,re,runpy,signal,os,stat,traceback
TG_DATACENTER_PORT=443
TG_DATACENTERS_V4=[_U,'149.154.167.51',_V,'149.154.167.91','149.154.171.5']
TG_DATACENTERS_V6=['2001:b28:f23d:f001::a','2001:67c:04e8:f002::a','2001:b28:f23d:f003::a','2001:67c:04e8:f004::a','2001:b28:f23f:f005::a']
TG_MIDDLE_PROXIES_V4={1:[(_U,8888)],-1:[(_U,8888)],2:[(_e,80)],-2:[(_e,80)],3:[(_V,8888)],-3:[(_V,8888)],4:[('91.108.4.136',8888)],-4:[('149.154.165.109',8888)],5:[(_f,8888)],-5:[(_f,8888)]}
TG_MIDDLE_PROXIES_V6={1:[(_g,8888)],-1:[(_g,8888)],2:[(_h,80)],-2:[(_h,80)],3:[(_i,8888)],-3:[(_i,8888)],4:[(_W,8888)],-4:[(_W,8888)],5:[('2001:b28:f23f:f005::d',8888)],-5:[(_W,8888)]}
PROXY_SECRET=bytes.fromhex('c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721'+'d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698'+'6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c'+'54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212')
SKIP_LEN=8
PREKEY_LEN=32
KEY_LEN=32
IV_LEN=16
HANDSHAKE_LEN=64
TLS_HANDSHAKE_LEN=1+2+2+512
PROTO_TAG_POS=56
DC_IDX_POS=60
MIN_CERT_LEN=1024
PROTO_TAG_ABRIDGED=b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE=_j
PROTO_TAG_SECURE=_k
CBC_PADDING=16
PADDING_FILLER=b'\x04\x00\x00\x00'
MIN_MSG_LEN=12
MAX_MSG_LEN=2**24
STAT_DURATION_BUCKETS=[.1,.5,1,2,5,15,60,300,600,1800,2**31-1]
my_ip_info={_M:_C,_H:_C}
used_handshakes=collections.OrderedDict()
client_ips=collections.OrderedDict()
last_client_ips={}
disable_middle_proxy=_B
is_time_skewed=_B
fake_cert_len=random.randrange(1024,4096)
mask_host_cached_ip=_C
last_clients_with_time_skew={}
last_clients_with_same_handshake=collections.Counter()
proxy_start_time=0
proxy_links=[]
stats=collections.Counter()
user_stats=collections.defaultdict(collections.Counter)
config={}
def init_config():
	T='0.0.0.0';S='SOCKS5_PORT';R='SOCKS5_HOST';Q='TLS_ONLY';P='SECURE_ONLY';O='USE_MIDDLE_PROXY';N='PORT';M='config';J='TLS_DOMAIN';G='USER_EXPIRATIONS';F='AD_TAG';E='USERS';D='MODES';global config
	if len(sys.argv)<2:A=runpy.run_module(M)
	elif len(sys.argv)==2:A=runpy.run_path(sys.argv[1])
	else:
		A={};A[N]=int(sys.argv[1]);K=sys.argv[2].split(',');A[E]={'user%d'%A:K[A].zfill(32)for A in range(len(K))};A[D]={_G:_B,_I:_A,_J:_A}
		if len(sys.argv)>3:A[F]=sys.argv[3]
		if len(sys.argv)>4:A[J]=sys.argv[4];A[D]={_G:_B,_I:_B,_J:_A}
	A={A:B for(A,B)in A.items()if A.isupper()};A.setdefault(N,3256);A.setdefault(E,{'tg':_l});A[F]=bytes.fromhex(A.get(F,''))
	for(C,H)in A[E].items():
		if not re.fullmatch('[0-9a-fA-F]{32}',H):L=re.sub('[^0-9a-fA-F]','',H).zfill(32)[:32];print_err('Bad secret for user %s, should be 32 hex chars, got %s. '%(C,H));print_err('Changing it to %s'%L);A[E][C]=L
	A.setdefault(O,len(A[F])==16);A.setdefault('PREFER_IPV6',socket.has_ipv6);A.setdefault('FAST_MODE',_A);B=A.get(D,{})
	if D not in A:B.setdefault(_G,_A);B.setdefault(_I,_A);B.setdefault(_J,_A)
	else:B.setdefault(_G,_B);B.setdefault(_I,_B);B.setdefault(_J,_B)
	I=_B
	if P in A:I=_A;B[_G]=not bool(A[P])
	if Q in A:
		I=_A
		if A[Q]:B[_G]=_B;B[_I]=_B
	if not B[_G]and not B[_I]and not B[_J]:print_err('No known modes enabled, enabling tls-only mode');B[_J]=_A
	if I:print_err('Legacy options SECURE_ONLY or TLS_ONLY detected');print_err('Please use MODES in your config instead:');print_err('MODES = {');print_err('    "classic": %s,'%B[_G]);print_err('    "secure": %s,'%B[_I]);print_err('    "tls": %s'%B[_J]);print_err('}')
	A[D]=B;A.setdefault('PROXY_PROTOCOL',_B);A.setdefault(J,_m);A.setdefault('MASK',_A);A.setdefault('MASK_HOST',A[J]);A.setdefault('MY_DOMAIN',_B);A.setdefault('MASK_PORT',443);A.setdefault(R,_C);A.setdefault(S,_C);A.setdefault('SOCKS5_USER',_C);A.setdefault('SOCKS5_PASS',_C)
	if A[R]and A[S]:A[O]=_B
	A.setdefault('USER_MAX_TCP_CONNS',{});A.setdefault(G,{})
	for C in A[G]:U=datetime.datetime.strptime(A[G][C],'%d/%m/%Y');A[G][C]=U
	A.setdefault('USER_DATA_QUOTA',{});A.setdefault('REPLAY_CHECK_LEN',65536);A.setdefault('IGNORE_TIME_SKEW',_B);A.setdefault('CLIENT_IPS_LEN',131072);A.setdefault('STATS_PRINT_PERIOD',600);A.setdefault('PROXY_INFO_UPDATE_PERIOD',24*60*60);A.setdefault('GET_TIME_PERIOD',10*60);A.setdefault('GET_CERT_LEN_PERIOD',random.randrange(4*60*60,6*60*60));A.setdefault('TO_CLT_BUFSIZE',(16384,100,131072));A.setdefault('TO_TG_BUFSIZE',65536);A.setdefault('CLIENT_KEEPALIVE',10*60);A.setdefault('CLIENT_HANDSHAKE_TIMEOUT',random.randrange(5,15));A.setdefault('CLIENT_ACK_TIMEOUT',5*60);A.setdefault('TG_CONNECT_TIMEOUT',10);A.setdefault('LISTEN_ADDR_IPV4',T);A.setdefault('LISTEN_ADDR_IPV6','::');A.setdefault('LISTEN_UNIX_SOCK','');A.setdefault('METRICS_PORT',_C);A.setdefault('METRICS_LISTEN_ADDR_IPV4',T);A.setdefault('METRICS_LISTEN_ADDR_IPV6',_C);A.setdefault('METRICS_WHITELIST',['127.0.0.1','::1']);A.setdefault('METRICS_EXPORT_LINKS',_B);A.setdefault('METRICS_PREFIX','mtprotoproxy_');config=type(M,(dict,),A)(A)
def apply_upstream_proxy_settings():
	B='origsocket'
	if config.SOCKS5_HOST and config.SOCKS5_PORT:
		import socks as A;print_err('Socket-proxy mode activated, it is incompatible with advertising and uvloop');A.set_default_proxy(A.PROXY_TYPE_SOCKS5,config.SOCKS5_HOST,config.SOCKS5_PORT,username=config.SOCKS5_USER,password=config.SOCKS5_PASS)
		if not hasattr(socket,B):socket.origsocket=socket.socket;socket.socket=A.socksocket
	elif hasattr(socket,B):socket.socket=socket.origsocket;del socket.origsocket
def try_use_cryptography_module():
	from cryptography.hazmat.primitives.ciphers import Cipher as A,algorithms as B,modes as C;from cryptography.hazmat.backends import default_backend as D
	class E:
		__slots__=_n,_o
		def __init__(A,cipher):B=cipher;A.encryptor=B.encryptor();A.decryptor=B.decryptor()
		def encrypt(A,data):return A.encryptor.update(data)
		def decrypt(A,data):return A.decryptor.update(data)
	def F(key,iv):F=int.to_bytes(iv,16,_E);G=A(B.AES(key),C.CTR(F),D());return E(G)
	def G(key,iv):F=A(B.AES(key),C.CBC(iv),D());return E(F)
	return F,G
def try_use_pycrypto_or_pycryptodome_module():
	from Crypto.Cipher import AES as A;from Crypto.Util import Counter as B
	def C(key,iv):C=B.new(128,initial_value=iv);return A.new(key,A.MODE_CTR,counter=C)
	def D(key,iv):return A.new(key,A.MODE_CBC,iv)
	return C,D
def use_slow_bundled_cryptography_module():
	import pyaes as A;B='To make the program a *lot* faster, please install cryptography module: ';B+='pip install cryptography\n';print(B,flush=_A,file=sys.stderr)
	class C:
		__slots__='mode',
		def __init__(A,mode):A.mode=mode
		def encrypt(C,data):B=A.Encrypter(C.mode,A.PADDING_NONE);return B.feed(data)+B.feed()
		def decrypt(C,data):B=A.Decrypter(C.mode,A.PADDING_NONE);return B.feed(data)+B.feed()
	def D(key,iv):B=A.Counter(iv);return A.AESModeOfOperationCTR(key,B)
	def E(key,iv):B=A.AESModeOfOperationCBC(key,iv);return C(B)
	return D,E
try:create_aes_ctr,create_aes_cbc=try_use_cryptography_module()
except ImportError:
	try:create_aes_ctr,create_aes_cbc=try_use_pycrypto_or_pycryptodome_module()
	except ImportError:create_aes_ctr,create_aes_cbc=use_slow_bundled_cryptography_module()
def print_err(*A):print(*A,file=sys.stderr,flush=_A)
def ensure_users_in_user_stats():
	global user_stats
	for A in config.USERS:user_stats[A].update()
def init_proxy_start_time():global proxy_start_time;proxy_start_time=time.time()
def update_stats(**A):global stats;stats.update(**A)
def update_user_stats(user,**A):global user_stats;user_stats[user].update(**A)
def update_durations(duration):
	global stats
	for A in STAT_DURATION_BUCKETS:
		if duration<=A:break
	update_stats(**{_p%str(A):1})
def get_curr_connects_count():
	global user_stats;A=0
	for(C,B)in user_stats.items():A+=B[_R]
	return A
def get_to_tg_bufsize():
	if isinstance(config.TO_TG_BUFSIZE,int):return config.TO_TG_BUFSIZE
	A,B,C=config.TO_TG_BUFSIZE;return C if get_curr_connects_count()<B else A
def get_to_clt_bufsize():
	if isinstance(config.TO_CLT_BUFSIZE,int):return config.TO_CLT_BUFSIZE
	A,B,C=config.TO_CLT_BUFSIZE;return C if get_curr_connects_count()<B else A
class MyRandom(random.Random):
	def __init__(A):super().__init__();B=bytes([random.randrange(256)for A in range(32)]);C=random.randrange(256**16);A.encryptor=create_aes_ctr(B,C);A.buffer=bytearray()
	def getrandbits(B,k):A=(k+7)//8;return int.from_bytes(B.getrandbytes(A),_E)>>A*8-k
	def getrandbytes(A,n):
		B=512
		while n>len(A.buffer):C=int.to_bytes(super().getrandbits(B*8),B,_E);A.buffer+=A.encryptor.encrypt(C)
		D=A.buffer[:n];A.buffer=A.buffer[n:];return bytes(D)
myrandom=MyRandom()
class TgConnectionPool:
	MAX_CONNS_IN_POOL=64
	def __init__(A):A.pools={}
	async def open_tg_connection(E,host,port,init_func=_C):
		B=init_func;D=asyncio.open_connection(host,port,limit=get_to_clt_bufsize());C,A=await asyncio.wait_for(D,timeout=config.TG_CONNECT_TIMEOUT);set_keepalive(A.get_extra_info(_K));set_bufsizes(A.get_extra_info(_K),get_to_clt_bufsize(),get_to_tg_bufsize())
		if B:return await asyncio.wait_for(B(host,port,C,A),timeout=config.TG_CONNECT_TIMEOUT)
		return C,A
	def register_host_port(A,host,port,init_func):
		D=init_func;C=port;B=host
		if(B,C,D)not in A.pools:A.pools[(B,C,D)]=[]
		while len(A.pools[(B,C,D)])<TgConnectionPool.MAX_CONNS_IN_POOL:E=asyncio.ensure_future(A.open_tg_connection(B,C,D));A.pools[(B,C,D)].append(E)
	async def get_connection(A,host,port,init_func=_C):
		D=init_func;C=port;B=host;A.register_host_port(B,C,D);F=_C
		for E in A.pools[(B,C,D)][:]:
			if E.done():
				if E.exception():A.pools[(B,C,D)].remove(E);continue
				H,G,*I=E.result()
				if G.transport.is_closing():A.pools[(B,C,D)].remove(E);continue
				if not F:A.pools[(B,C,D)].remove(E);F=H,G,*I
		A.register_host_port(B,C,D)
		if F:return F
		return await A.open_tg_connection(B,C,D)
tg_connection_pool=TgConnectionPool()
class LayeredStreamReaderBase:
	__slots__=_q,
	def __init__(A,upstream):A.upstream=upstream
	async def read(A,n):return await A.upstream.read(n)
	async def readexactly(A,n):return await A.upstream.readexactly(n)
class LayeredStreamWriterBase:
	__slots__=_q,
	def __init__(A,upstream):A.upstream=upstream
	def write(A,data,extra={}):return A.upstream.write(data)
	def write_eof(A):return A.upstream.write_eof()
	async def drain(A):return await A.upstream.drain()
	def close(A):return A.upstream.close()
	def abort(A):return A.upstream.transport.abort()
	def get_extra_info(A,name):return A.upstream.get_extra_info(name)
	@property
	def transport(self):return self.upstream.transport
class FakeTLSStreamReader(LayeredStreamReaderBase):
	__slots__='buf',
	def __init__(A,upstream):A.upstream=upstream;A.buf=bytearray()
	async def read(A,n,ignore_buf=_B):
		if A.buf and not ignore_buf:C=A.buf;A.buf=bytearray();return bytes(C)
		while _A:
			B=await A.upstream.readexactly(1)
			if not B:return _F
			if B not in[_X,b'\x17']:print_err('BUG: bad tls type %s in FakeTLSStreamReader'%B);return _F
			D=await A.upstream.readexactly(2)
			if D!=_Y:print_err('BUG: unknown version %s in FakeTLSStreamReader'%D);return _F
			E=int.from_bytes(await A.upstream.readexactly(2),_E);C=await A.upstream.readexactly(E)
			if B==_X:continue
			return C
	async def readexactly(A,n):
		while len(A.buf)<n:
			B=await A.read(1,ignore_buf=_A)
			if not B:return _F
			A.buf+=B
		C,A.buf=A.buf[:n],A.buf[n:];return bytes(C)
class FakeTLSStreamWriter(LayeredStreamWriterBase):
	__slots__=()
	def __init__(A,upstream):A.upstream=upstream
	def write(C,data,extra={}):
		A=data;D=16384+24
		for B in range(0,len(A),D):E=min(B+D,len(A));C.upstream.write(b'\x17\x03\x03'+int.to_bytes(E-B,2,_E));C.upstream.write(A[B:E])
		return len(A)
class CryptoWrappedStreamReader(LayeredStreamReaderBase):
	__slots__=_o,_r,'buf'
	def __init__(A,upstream,decryptor,block_size=1):A.upstream=upstream;A.decryptor=decryptor;A.block_size=block_size;A.buf=bytearray()
	async def read(A,n):
		if A.buf:D=bytes(A.buf);A.buf.clear();return D
		else:
			B=await A.upstream.read(n)
			if not B:return _F
			C=-len(B)%A.block_size
			if C>0:B+=A.upstream.readexactly(C)
			return A.decryptor.decrypt(B)
	async def readexactly(A,n):
		if n>len(A.buf):B=n-len(A.buf);C=-B%A.block_size;D=B+C;E=await A.upstream.readexactly(D);A.buf+=A.decryptor.decrypt(E)
		F=bytes(A.buf[:n]);A.buf=A.buf[n:];return F
class CryptoWrappedStreamWriter(LayeredStreamWriterBase):
	__slots__=_n,_r
	def __init__(A,upstream,encryptor,block_size=1):A.upstream=upstream;A.encryptor=encryptor;A.block_size=block_size
	def write(A,data,extra={}):
		B=data
		if len(B)%A.block_size!=0:print_err('BUG: writing %d bytes not aligned to block size %d'%(len(B),A.block_size));return 0
		C=A.encryptor.encrypt(B);return A.upstream.write(C)
class MTProtoFrameStreamReader(LayeredStreamReaderBase):
	__slots__=_s,
	def __init__(A,upstream,seq_no=0):A.upstream=upstream;A.seq_no=seq_no
	async def read(A,buf_size):
		C=await A.upstream.readexactly(4);B=int.from_bytes(C,_D)
		while B==4:C=await A.upstream.readexactly(4);B=int.from_bytes(C,_D)
		F=B%len(PADDING_FILLER)!=0
		if not MIN_MSG_LEN<=B<=MAX_MSG_LEN or F:print_err('msg_len is bad, closing connection',B);return _F
		D=await A.upstream.readexactly(4);G=int.from_bytes(D,_D,signed=_A)
		if G!=A.seq_no:print_err('unexpected seq_no');return _F
		A.seq_no+=1;E=await A.upstream.readexactly(B-4-4-4);H=await A.upstream.readexactly(4);I=int.from_bytes(H,_D);J=binascii.crc32(C+D+E)
		if J!=I:return _F
		return E
class MTProtoFrameStreamWriter(LayeredStreamWriterBase):
	__slots__=_s,
	def __init__(A,upstream,seq_no=0):A.upstream=upstream;A.seq_no=seq_no
	def write(A,msg,extra={}):D=int.to_bytes(len(msg)+4+4+4,4,_D);E=int.to_bytes(A.seq_no,4,_D,signed=_A);A.seq_no+=1;B=D+E+msg;F=int.to_bytes(binascii.crc32(B),4,_D);C=B+F;G=PADDING_FILLER*(-len(C)%CBC_PADDING//len(PADDING_FILLER));return A.upstream.write(C+G)
class MTProtoCompactFrameStreamReader(LayeredStreamReaderBase):
	__slots__=()
	async def read(B,buf_size):
		C=await B.upstream.readexactly(1);A=int.from_bytes(C,_D);D={_O:_B}
		if A>=128:D[_O]=_A;A-=128
		if A==127:C=await B.upstream.readexactly(3);A=int.from_bytes(C,_D)
		A*=4;E=await B.upstream.readexactly(A);return E,D
class MTProtoCompactFrameStreamWriter(LayeredStreamWriterBase):
	__slots__=()
	def write(C,data,extra={}):
		A=data;D=127;E=256**3
		if len(A)%4!=0:print_err('BUG: MTProtoFrameStreamWriter attempted to send msg with len',len(A));return 0
		if extra.get(_S):return C.upstream.write(A[::-1])
		B=len(A)//4
		if B<D:return C.upstream.write(bytes([B])+A)
		elif B<E:return C.upstream.write(b'\x7f'+int.to_bytes(B,3,_D)+A)
		else:print_err('Attempted to send too large pkt len =',len(A));return 0
class MTProtoIntermediateFrameStreamReader(LayeredStreamReaderBase):
	__slots__=()
	async def read(B,buf_size):
		D=await B.upstream.readexactly(4);A=int.from_bytes(D,_D);C={}
		if A>2147483648:C[_O]=_A;A-=2147483648
		E=await B.upstream.readexactly(A);return E,C
class MTProtoIntermediateFrameStreamWriter(LayeredStreamWriterBase):
	__slots__=()
	def write(B,data,extra={}):
		A=data
		if extra.get(_S):return B.upstream.write(A)
		else:return B.upstream.write(int.to_bytes(len(A),4,_D)+A)
class MTProtoSecureIntermediateFrameStreamReader(LayeredStreamReaderBase):
	__slots__=()
	async def read(C,buf_size):
		E=await C.upstream.readexactly(4);A=int.from_bytes(E,_D);D={}
		if A>2147483648:D[_O]=_A;A-=2147483648
		B=await C.upstream.readexactly(A)
		if A%4!=0:F=A-A%4;B=B[:F]
		return B,D
class MTProtoSecureIntermediateFrameStreamWriter(LayeredStreamWriterBase):
	__slots__=()
	def write(B,data,extra={}):
		A=data;D=4
		if extra.get(_S):return B.upstream.write(A)
		else:C=myrandom.randrange(D);E=myrandom.getrandbytes(C);F=int.to_bytes(len(A)+C,4,_D);return B.upstream.write(F+A+E)
class ProxyReqStreamReader(LayeredStreamReaderBase):
	__slots__=()
	async def read(C,msg):
		D=b'\r\xda\x03D';E=b'\xa24\xb6^';F=b'\x9b@\xac;';G=b'\xdf\xa20W';A=await C.upstream.read(1)
		if len(A)<4:return _F
		B=A[:4]
		if B==E:return _F
		if B==D:K,H,I=A[4:8],A[8:16],A[16:];return I
		if B==F:H,J=A[4:12],A[12:16];return J,{_S:_A}
		if B==G:return _F,{_Z:_A}
		print_err('unknown rpc ans type:',B);return _F,{_Z:_A}
class ProxyReqStreamWriter(LayeredStreamWriterBase):
	__slots__='remote_ip_port','our_ip_port','out_conn_id','proto_tag'
	def __init__(A,upstream,cl_ip,cl_port,my_ip,my_port,proto_tag):
		D=b'\xff\xff';C=my_ip;B=cl_ip;A.upstream=upstream
		if _N not in B:A.remote_ip_port=_L*10+D;A.remote_ip_port+=socket.inet_pton(socket.AF_INET,B)
		else:A.remote_ip_port=socket.inet_pton(socket.AF_INET6,B)
		A.remote_ip_port+=int.to_bytes(cl_port,4,_D)
		if _N not in C:A.our_ip_port=_L*10+D;A.our_ip_port+=socket.inet_pton(socket.AF_INET,C)
		else:A.our_ip_port=socket.inet_pton(socket.AF_INET6,C)
		A.our_ip_port+=int.to_bytes(my_port,4,_D);A.out_conn_id=myrandom.getrandbytes(8);A.proto_tag=proto_tag
	def write(A,msg,extra={}):
		D=msg;F=b'\xee\xf1\xce6';G=b'\x18\x00\x00\x00';H=b'\xae&\x1e\xdb';I=b'\x00\x00\x00';J=2;K=8;L=4096;M=131072;N=134217728;E=536870912;O=1073741824;P=2147483648
		if len(D)%4!=0:print_err('BUG: attempted to send msg with len %d'%len(D));return 0
		B=K|L|M
		if A.proto_tag==PROTO_TAG_ABRIDGED:B|=O
		elif A.proto_tag==PROTO_TAG_INTERMEDIATE:B|=E
		elif A.proto_tag==PROTO_TAG_SECURE:B|=E|N
		if extra.get(_O):B|=P
		if D.startswith(_L*8):B|=J
		C=bytearray();C+=F+int.to_bytes(B,4,_D)+A.out_conn_id;C+=A.remote_ip_port+A.our_ip_port+G+H;C+=bytes([len(config.AD_TAG)])+config.AD_TAG+I;C+=D;return A.upstream.write(C)
def try_setsockopt(sock,level,option,value):
	try:sock.setsockopt(level,option,value)
	except OSError as A:pass
def set_keepalive(sock,interval=40,attempts=5):
	B=interval;A=sock;A.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
	if hasattr(socket,'TCP_KEEPIDLE'):try_setsockopt(A,socket.IPPROTO_TCP,socket.TCP_KEEPIDLE,B)
	if hasattr(socket,'TCP_KEEPINTVL'):try_setsockopt(A,socket.IPPROTO_TCP,socket.TCP_KEEPINTVL,B)
	if hasattr(socket,'TCP_KEEPCNT'):try_setsockopt(A,socket.IPPROTO_TCP,socket.TCP_KEEPCNT,attempts)
def set_ack_timeout(sock,timeout):
	if hasattr(socket,'TCP_USER_TIMEOUT'):try_setsockopt(sock,socket.IPPROTO_TCP,socket.TCP_USER_TIMEOUT,timeout*1000)
def set_bufsizes(sock,recv_buf,send_buf):try_setsockopt(sock,socket.SOL_SOCKET,socket.SO_RCVBUF,recv_buf);try_setsockopt(sock,socket.SOL_SOCKET,socket.SO_SNDBUF,send_buf)
def set_instant_rst(sock):
	A=b'\x01\x00\x00\x00\x00\x00\x00\x00'
	if hasattr(socket,'SO_LINGER'):try_setsockopt(sock,socket.SOL_SOCKET,socket.SO_LINGER,A)
def gen_x25519_public_key():A=2**255-19;B=myrandom.randrange(A);return int.to_bytes(B*B%A,length=32,byteorder=_D)
async def connect_reader_to_writer(reader,writer):
	A=writer;C=8192
	try:
		while _A:
			B=await reader.read(C)
			if not B:
				if not A.transport.is_closing():A.write_eof();await A.drain()
				return
			A.write(B);await A.drain()
	except(OSError,asyncio.IncompleteReadError)as D:pass
async def handle_bad_client(reader_clt,writer_clt,handshake):
	F=handshake;E=reader_clt;B=writer_clt;C=8192;K=5;global mask_host_cached_ip;update_stats(connects_bad=1)
	if B.transport.is_closing():return
	set_bufsizes(B.get_extra_info(_K),C,C)
	if not config.MASK or F is _C:
		while await E.read(C):0
		return
	A=_C
	try:
		L=mask_host_cached_ip or config.MASK_HOST;M=asyncio.open_connection(L,config.MASK_PORT,limit=C);N,A=await asyncio.wait_for(M,timeout=K)
		if not mask_host_cached_ip:mask_host_cached_ip=A.get_extra_info(_P)[0]
		A.write(F);await A.drain();O=connect_reader_to_writer(N,B);P=connect_reader_to_writer(E,A);G=asyncio.ensure_future(O);H=asyncio.ensure_future(P);await asyncio.wait([G,H],return_when=asyncio.FIRST_COMPLETED);G.cancel();H.cancel()
		if B.transport.is_closing():return
		if not A.transport.is_closing():
			D=A.get_extra_info(_K);I=socket.socket(D.family,D.type,D.proto,D.fileno())
			try:I.shutdown(socket.SHUT_WR)
			except OSError as J:set_instant_rst(B.get_extra_info(_K))
			finally:I.detach()
		else:set_instant_rst(B.get_extra_info(_K))
	except ConnectionRefusedError as J:return
	except(OSError,asyncio.TimeoutError)as J:return
	finally:
		if A is not _C:A.transport.abort()
async def handle_fake_tls_handshake(handshake,reader,writer,peer):
	J=reader;F=peer;E=writer;D=handshake;global used_handshakes;global client_ips;global last_client_ips;global last_clients_with_time_skew;global last_clients_with_same_handshake;global fake_cert_len;U=-20*60;V=10*60;G=_Y;W=b'\x13\x01';X=_X+G+b'\x00\x01\x01';Y=b'\x17'+G;A=32;M=16;C=11;N=C+A;O=N+1;P=b'\x00.'+b'\x003\x00$'+b'\x00\x1d\x00 ';P+=gen_x25519_public_key()+b'\x00+\x00\x02\x03\x04';H=D[C:C+A]
	if H[:M]in used_handshakes:last_clients_with_same_handshake[F[0]]+=1;return _B
	Q=D[N];Z=D[O:O+Q]
	for a in config.USERS:
		R=bytes.fromhex(config.USERS[a]);b=D[:C]+_L*A+D[C+A:];K=hmac.new(R,b,digestmod=hashlib.sha256).digest();S=bytes(H[A]^K[A]for A in range(A));c=S.startswith(_L*(A-4))
		if not c:continue
		L=int.from_bytes(S[-4:],_D);d=U<time.time()-L<V;e=L<60*60*24*1000;f=config.IGNORE_TIME_SKEW or is_time_skewed or e
		if not d and not f:last_clients_with_time_skew[F[0]]=(time.time()-L)//60;continue
		T=myrandom.getrandbytes(fake_cert_len);I=G+_L*A+bytes([Q])+Z;I+=W+_L+P;B=b'\x16'+G+int.to_bytes(len(I)+4,2,_E);B+=b'\x02'+int.to_bytes(len(I),3,_E)+I;B+=X+Y;B+=int.to_bytes(len(T),2,_E)+T;K=hmac.new(R,msg=H+B,digestmod=hashlib.sha256).digest();B=B[:C]+K+B[C+A:];E.write(B);await E.drain()
		if config.REPLAY_CHECK_LEN>0:
			while len(used_handshakes)>=config.REPLAY_CHECK_LEN:used_handshakes.popitem(last=_B)
			used_handshakes[H[:M]]=_A
		if config.CLIENT_IPS_LEN>0:
			while len(client_ips)>=config.CLIENT_IPS_LEN:client_ips.popitem(last=_B)
			if F[0]not in client_ips:client_ips[F[0]]=_A;last_client_ips[F[0]]=_A
		J=FakeTLSStreamReader(J);E=FakeTLSStreamWriter(E);return J,E
	return _B
async def handle_proxy_protocol(reader,peer=_C):
	G=peer;F=reader;K=b'PROXY ';J=6;L=b'TCP4';M=b'TCP6';N=b'UNKNOWN';O=b'\r\n\r\n\x00\r\nQUIT\n';P=16;Q=0;R=1;S=2;A=await F.readexactly(J)
	if A.startswith(K):
		A+=await F.readuntil(b'\r\n');T,C,*B=A[:-2].split(b' ')
		if C in(L,M):
			if len(B)==4:D=B[0].decode(_a);E=int(B[2].decode(_a));return D,E
		elif C==N:return G
		return _B
	A+=await F.readexactly(P-J)
	if A.startswith(O):
		H=A[12]
		if H&240!=32:return _B
		I=int.from_bytes(A[14:16],_E);B=await F.readexactly(I)
		if H==33:
			C=A[13]>>4
			if C==R:
				if I>=(4+2)*2:D=socket.inet_ntop(socket.AF_INET,B[:4]);E=int.from_bytes(B[8:10],_E);return D,E
			elif C==S:
				if I>=(16+2)*2:D=socket.inet_ntop(socket.AF_INET6,B[:16]);E=int.from_bytes(B[32:34],_E);return D,E
			elif C==Q:return G
		elif H==32:return G
	return _B
async def handle_handshake(reader,writer):
	P='unknown ip';C=writer;A=reader;global used_handshakes;global client_ips;global last_client_ips;global last_clients_with_same_handshake;Q=_t
	if C.transport.is_closing()or C.get_extra_info(_P)is _C:return _B
	D=C.get_extra_info(_P)[:2]
	if not D:D=P,0
	if config.PROXY_PROTOCOL:
		R=D[0]if D else P;D=await handle_proxy_protocol(A,D)
		if not D:print_err('Client from %s sent bad proxy protocol headers'%R);await handle_bad_client(A,C,_C);return _B
	E=_A;B=_F
	for S in Q:
		B+=await A.readexactly(1)
		if B[-1]!=S:E=_B;break
	if E:
		B+=await A.readexactly(TLS_HANDSHAKE_LEN-len(B));H=await handle_fake_tls_handshake(B,A,C,D)
		if not H:await handle_bad_client(A,C,B);return _B
		A,C=H;B=await A.readexactly(HANDSHAKE_LEN)
	else:
		if not config.MODES[_G]and not config.MODES[_I]:await handle_bad_client(A,C,B);return _B
		B+=await A.readexactly(HANDSHAKE_LEN-len(B))
	F=B[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN];T,U=F[:PREKEY_LEN],F[PREKEY_LEN:];I=B[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN][::-1];V,J=I[:PREKEY_LEN],I[PREKEY_LEN:]
	if F in used_handshakes:last_clients_with_same_handshake[D[0]]+=1;await handle_bad_client(A,C,B);return _B
	for K in config.USERS:
		L=bytes.fromhex(config.USERS[K]);W=hashlib.sha256(T+L).digest();M=create_aes_ctr(key=W,iv=int.from_bytes(U,_E));N=hashlib.sha256(V+L).digest();X=create_aes_ctr(key=N,iv=int.from_bytes(J,_E));O=M.decrypt(B);G=O[PROTO_TAG_POS:PROTO_TAG_POS+4]
		if G not in(PROTO_TAG_ABRIDGED,PROTO_TAG_INTERMEDIATE,PROTO_TAG_SECURE):continue
		if G==PROTO_TAG_SECURE:
			if E and not config.MODES[_J]:continue
			if not E and not config.MODES[_I]:continue
		elif not config.MODES[_G]:continue
		Y=int.from_bytes(O[DC_IDX_POS:DC_IDX_POS+2],_D,signed=_A)
		if config.REPLAY_CHECK_LEN>0:
			while len(used_handshakes)>=config.REPLAY_CHECK_LEN:used_handshakes.popitem(last=_B)
			used_handshakes[F]=_A
		if config.CLIENT_IPS_LEN>0:
			while len(client_ips)>=config.CLIENT_IPS_LEN:client_ips.popitem(last=_B)
			if D[0]not in client_ips:client_ips[D[0]]=_A;last_client_ips[D[0]]=_A
		A=CryptoWrappedStreamReader(A,M);C=CryptoWrappedStreamWriter(C,X);return A,C,G,K,Y,N+J,D
	await handle_bad_client(A,C,B);return _B
async def do_direct_handshake(proto_tag,dc_idx,dec_key_and_iv=_C):
	C=dec_key_and_iv;B=dc_idx;J=[b'\xef'];K=[b'HEAD',b'POST',b'GET ',_j,_k,b'\x16\x03\x01\x02'];L=[_b];global my_ip_info;global tg_connection_pool;B=abs(B)-1
	if my_ip_info[_H]and(config.PREFER_IPV6 or not my_ip_info[_M]):
		if not 0<=B<len(TG_DATACENTERS_V6):return _B
		E=TG_DATACENTERS_V6[B]
	else:
		if not 0<=B<len(TG_DATACENTERS_V4):return _B
		E=TG_DATACENTERS_V4[B]
	try:F,D=await tg_connection_pool.get_connection(E,TG_DATACENTER_PORT)
	except ConnectionRefusedError as G:print_err('Got connection refused while trying to connect to',E,TG_DATACENTER_PORT);return _B
	except ConnectionAbortedError as G:print_err(_u%(B,addr,port,G));return _B
	except(OSError,asyncio.TimeoutError)as G:print_err('Unable to connect to',E,TG_DATACENTER_PORT);return _B
	while _A:
		A=bytearray(myrandom.getrandbytes(HANDSHAKE_LEN))
		if A[:1]in J:continue
		if A[:4]in K:continue
		if A[4:8]in L:continue
		break
	A[PROTO_TAG_POS:PROTO_TAG_POS+4]=proto_tag
	if C:A[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN]=C[::-1]
	A=bytes(A);C=A[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN][::-1];M,N=C[:KEY_LEN],C[KEY_LEN:];O=create_aes_ctr(key=M,iv=int.from_bytes(N,_E));H=A[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN];P,Q=H[:KEY_LEN],H[KEY_LEN:];I=create_aes_ctr(key=P,iv=int.from_bytes(Q,_E));R=A[:PROTO_TAG_POS]+I.encrypt(A)[PROTO_TAG_POS:];D.write(R);await D.drain();F=CryptoWrappedStreamReader(F,O);D=CryptoWrappedStreamWriter(D,I);return F,D
def get_middleproxy_aes_key_and_iv(nonce_srv,nonce_clt,clt_ts,srv_ip,clt_port,purpose,clt_ip,srv_port,middleproxy_secret,clt_ipv6=_C,srv_ipv6=_C):
	G=srv_ipv6;F=clt_ipv6;E=nonce_clt;D=nonce_srv;C=clt_ip;B=srv_ip;H=_b
	if not C or not B:C=H;B=H
	A=bytearray();A+=D+E+clt_ts+B+clt_port+purpose+C+srv_port;A+=middleproxy_secret+D
	if F and G:A+=F+G
	A+=E;I=hashlib.md5(A[1:]).digest();J=hashlib.sha1(A).digest();K=I[:12]+J;L=hashlib.md5(A[2:]).digest();return K,L
async def middleproxy_handshake(host,port,reader_tgt,writer_tgt):
	' The most logic of middleproxy handshake, launched in pool ';W=b'IPIPPRPDTIME';B=reader_tgt;A=writer_tgt;M=-2;X=16;N=b'\xf5\xee\x82v';O=b'\xaa\x87\xcbz';Y=_b;P=b'\x01\x00\x00\x00';Z=32;a=32;A=MTProtoFrameStreamWriter(A,M);Q=PROXY_SECRET[:4];F=int.to_bytes(int(time.time())%256**4,4,_D);G=myrandom.getrandbytes(X);b=O+Q+P+F+G;A.write(b);await A.drain();B=MTProtoFrameStreamReader(B,M);C=await B.read(get_to_clt_bufsize())
	if len(C)!=Z:raise ConnectionAbortedError('bad rpc answer length')
	c,d,e,r,R=C[:4],C[4:8],C[8:12],C[12:16],C[16:32]
	if c!=O or d!=Q or e!=P:raise ConnectionAbortedError('bad rpc answer')
	H,f=A.upstream.get_extra_info(_P)[:2];D,S=A.upstream.get_extra_info('sockname')[:2];g=_N in H
	if not g:
		if my_ip_info[_M]:D=my_ip_info[_M]
		I=socket.inet_pton(socket.AF_INET,H)[::-1];J=socket.inet_pton(socket.AF_INET,D)[::-1];K=_C;L=_C
	else:
		if my_ip_info[_H]:D=my_ip_info[_H]
		I=_C;J=_C;K=socket.inet_pton(socket.AF_INET6,H);L=socket.inet_pton(socket.AF_INET6,D)
	T=int.to_bytes(f,2,_D);U=int.to_bytes(S,2,_D);h,i=get_middleproxy_aes_key_and_iv(nonce_srv=R,nonce_clt=G,clt_ts=F,srv_ip=I,clt_port=U,purpose=b'CLIENT',clt_ip=J,srv_port=T,middleproxy_secret=PROXY_SECRET,clt_ipv6=L,srv_ipv6=K);j,k=get_middleproxy_aes_key_and_iv(nonce_srv=R,nonce_clt=G,clt_ts=F,srv_ip=I,clt_port=U,purpose=b'SERVER',clt_ip=J,srv_port=T,middleproxy_secret=PROXY_SECRET,clt_ipv6=L,srv_ipv6=K);l=create_aes_cbc(key=h,iv=i);m=create_aes_cbc(key=j,iv=k);V=W;n=W;o=N+Y+V+n;A.upstream=CryptoWrappedStreamWriter(A.upstream,l,block_size=16);A.write(o);await A.drain();B.upstream=CryptoWrappedStreamReader(B.upstream,m,block_size=16);E=await B.read(1)
	if len(E)!=a:raise ConnectionAbortedError('bad rpc handshake answer length')
	p,s,t,q=E[:4],E[4:8],E[8:20],E[20:32]
	if p!=N or q!=V:raise ConnectionAbortedError('bad rpc handshake answer')
	return B,A,D,S
async def do_middleproxy_handshake(proto_tag,dc_idx,cl_ip,cl_port):
	A=dc_idx;global my_ip_info;global tg_connection_pool;G=my_ip_info[_H]and(config.PREFER_IPV6 or not my_ip_info[_M])
	if G:
		if A not in TG_MIDDLE_PROXIES_V6:return _B
		B,C=myrandom.choice(TG_MIDDLE_PROXIES_V6[A])
	else:
		if A not in TG_MIDDLE_PROXIES_V4:return _B
		B,C=myrandom.choice(TG_MIDDLE_PROXIES_V4[A])
	try:H=await tg_connection_pool.get_connection(B,C,middleproxy_handshake);D,E,I,J=H
	except ConnectionRefusedError as F:print_err('The Telegram server %d (%s %s) is refusing connections'%(A,B,C));return _B
	except ConnectionAbortedError as F:print_err(_u%(A,B,C,F));return _B
	except(OSError,asyncio.TimeoutError)as F:print_err('Unable to connect to the Telegram server %d (%s %s)'%(A,B,C));return _B
	E=ProxyReqStreamWriter(E,cl_ip,cl_port,I,J,proto_tag);D=ProxyReqStreamReader(D);return D,E
async def tg_connect_reader_to_writer(rd,wr,user,rd_buf_size,is_upstream):
	try:
		while _A:
			A=await rd.read(rd_buf_size)
			if isinstance(A,tuple):A,B=A
			else:B={}
			if B.get(_Z):continue
			if not A:wr.write_eof();await wr.drain();return
			else:
				if is_upstream:update_user_stats(user,octets_from_client=len(A),msgs_from_client=1)
				else:update_user_stats(user,octets_to_client=len(A),msgs_to_client=1)
				wr.write(A,B);await wr.drain()
	except(OSError,asyncio.IncompleteReadError)as C:pass
async def handle_client(reader_clt,writer_clt):
	C=reader_clt;B=writer_clt;set_keepalive(B.get_extra_info(_K),config.CLIENT_KEEPALIVE,attempts=3);set_ack_timeout(B.get_extra_info(_K),config.CLIENT_ACK_TIMEOUT);set_bufsizes(B.get_extra_info(_K),get_to_tg_bufsize(),get_to_clt_bufsize());update_stats(connects_all=1)
	try:H=await asyncio.wait_for(handle_handshake(C,B),timeout=config.CLIENT_HANDSHAKE_TIMEOUT)
	except asyncio.TimeoutError:update_stats(handshake_timeouts=1);return
	if not H:return
	C,B,D,A,F,M,N=H;O,P=N;update_user_stats(A,connects=1);G=not config.USE_MIDDLE_PROXY or disable_middle_proxy
	if G:
		if config.FAST_MODE:E=await do_direct_handshake(D,F,dec_key_and_iv=M)
		else:E=await do_direct_handshake(D,F)
	else:E=await do_middleproxy_handshake(D,F,O,P)
	if not E:return
	I,J=E
	if G and config.FAST_MODE:
		class Q:
			def encrypt(A,data):return data
		class R:
			def decrypt(A,data):return data
		I.decryptor=R();B.encryptor=Q()
	if not G:
		if D==PROTO_TAG_ABRIDGED:C=MTProtoCompactFrameStreamReader(C);B=MTProtoCompactFrameStreamWriter(B)
		elif D==PROTO_TAG_INTERMEDIATE:C=MTProtoIntermediateFrameStreamReader(C);B=MTProtoIntermediateFrameStreamWriter(B)
		elif D==PROTO_TAG_SECURE:C=MTProtoSecureIntermediateFrameStreamReader(C);B=MTProtoSecureIntermediateFrameStreamWriter(B)
		else:return
	S=tg_connect_reader_to_writer(I,B,A,get_to_clt_bufsize(),_B);T=tg_connect_reader_to_writer(C,J,A,get_to_tg_bufsize(),_A);K=asyncio.ensure_future(S);L=asyncio.ensure_future(T);update_user_stats(A,curr_connects=1);U=A in config.USER_MAX_TCP_CONNS and user_stats[A][_R]>config.USER_MAX_TCP_CONNS[A];V=A in config.USER_EXPIRATIONS and datetime.datetime.now()>config.USER_EXPIRATIONS[A];W=A in config.USER_DATA_QUOTA and user_stats[A][_c]+user_stats[A][_d]>config.USER_DATA_QUOTA[A]
	if not U and not V and not W:X=time.time();await asyncio.wait([K,L],return_when=asyncio.FIRST_COMPLETED);update_durations(time.time()-X)
	update_user_stats(A,curr_connects=-1);K.cancel();L.cancel();J.transport.abort()
async def handle_client_wrapper(reader,writer):
	A=writer
	try:await handle_client(reader,A)
	except(asyncio.IncompleteReadError,asyncio.CancelledError):pass
	except(ConnectionResetError,TimeoutError,BrokenPipeError):pass
	except Exception:traceback.print_exc()
	finally:A.transport.abort()
def make_metrics_pkt(metrics):
	C=[];F=set()
	for(A,J,K,D)in metrics:
		A=config.METRICS_PREFIX+A
		if A not in F:C.append('# HELP %s %s'%(A,K));C.append('# TYPE %s %s'%(A,J));F.add(A)
		if isinstance(D,dict):
			G=[]
			for(H,E)in D.items():
				if H==_Q:continue
				E=E.replace('"','\\"');G.append('%s="%s"'%(H,E))
			C.append('%s{%s} %s'%(A,','.join(G),D[_Q]))
		else:C.append('%s %s'%(A,D))
	I='\n'.join(C)+'\n';B=[];B.append('HTTP/1.1 200 OK');B.append(_v);B.append('Content-Length: %d'%len(I));B.append('Content-Type: text/plain; version=0.0.4; charset=utf-8');B.append('Date: %s'%time.strftime('%a, %d %b %Y %H:%M:%S GMT',time.gmtime()));L='\r\n'.join(B);M=L+_w+I;return M
async def handle_metrics(reader,writer):
	N='handshake_timeouts';M='connects_all';L='connects_bad';C=writer;A='counter';global stats;global user_stats;global my_ip_info;global proxy_start_time;global proxy_links;global last_clients_with_time_skew;global last_clients_with_same_handshake;O=C.get_extra_info(_P)[0]
	if O not in config.METRICS_WHITELIST:C.close();return
	try:
		B=[];B.append(['uptime',A,'proxy uptime',time.time()-proxy_start_time]);B.append([L,A,'connects with bad secret',stats[L]]);B.append([M,A,'incoming connects',stats[M]]);B.append([N,A,'number of timed out handshakes',stats[N]])
		if config.METRICS_EXPORT_LINKS:
			for P in proxy_links:H=P.copy();H[_Q]=1;B.append(['proxy_link_info',A,'the proxy link info',H])
		I=0
		for D in STAT_DURATION_BUCKETS:J=D if D!=STAT_DURATION_BUCKETS[-1]else'+Inf';E={'bucket':'%s-%s'%(I,J),_Q:stats[_p%str(D)]};B.append(['connects_by_duration',A,'connects by duration',E]);I=J
		Q=[['user_connects',A,'user connects',_x],['user_connects_curr','gauge','current user connects',_R],['user_octets',A,'octets proxied for user','octets_from_client+octets_to_client'],['user_msgs',A,'msgs proxied for user','msgs_from_client+msgs_to_client'],['user_octets_from',A,'octets proxied from user',_d],['user_octets_to',A,'octets proxied to user',_c],['user_msgs_from',A,'msgs proxied from user',_y],['user_msgs_to',A,'msgs proxied to user',_z]]
		for(R,S,T,F)in Q:
			for(U,K)in user_stats.items():
				if'+'in F:
					G=0
					for V in F.split('+'):G+=K[V]
				else:G=K[F]
				E={_T:U,_Q:G};B.append([R,S,T,E])
		W=make_metrics_pkt(B);C.write(W.encode());await C.drain()
	except Exception:traceback.print_exc()
	finally:C.close()
async def stats_printer():
	global user_stats;global last_client_ips;global last_clients_with_time_skew;global last_clients_with_same_handshake
	while _A:
		await asyncio.sleep(config.STATS_PRINT_PERIOD);print('Stats for',time.strftime('%d.%m.%Y %H:%M:%S'))
		for(C,A)in user_stats.items():print('%s: %d connects (%d current), %.2f MB, %d msgs'%(C,A[_x],A[_R],(A[_d]+A[_c])/1000000,A[_y]+A[_z]))
		print(flush=_A)
		if last_client_ips:
			print('New IPs:')
			for B in last_client_ips:print(B)
			print(flush=_A);last_client_ips.clear()
		if last_clients_with_time_skew:
			print('Clients with time skew (possible replay-attackers):')
			for(B,D)in last_clients_with_time_skew.items():print('%s, clocks were %d minutes behind'%(B,D))
			print(flush=_A);last_clients_with_time_skew.clear()
		if last_clients_with_same_handshake:
			print('Clients with duplicate handshake (likely replay-attackers):')
			for(B,E)in last_clients_with_same_handshake.items():print('%s, %d times'%(B,E))
			print(flush=_A);last_clients_with_same_handshake.clear()
async def make_https_req(url,host='core.telegram.org'):' Make request, return resp body and headers. ';C=443;A=urllib.parse.urlparse(url);D='\r\n'.join(['GET %s HTTP/1.1','Host: %s',_v])+_w;E,B=await asyncio.open_connection(A.netloc,C,ssl=_A);F=D%(urllib.parse.quote(A.path),host);B.write(F.encode('utf8'));G=await E.read();B.close();H,I=G.split(b'\r\n\r\n',1);return H,I
def gen_tls_client_hello_msg(server_name):B=server_name;A=bytearray();A+=_t+myrandom.getrandbytes(32);A+=b' '+myrandom.getrandbytes(32);A+=b'\x00"JJ\x13\x01\x13\x02\x13\x03\xc0+\xc0/\xc0,\xc00\xcc\xa9';A+=b'\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x00\n\x01\x00\x01\x91';A+=b'\xda\xda\x00\x00\x00\x00';A+=int.to_bytes(len(B)+5,2,_E);A+=int.to_bytes(len(B)+3,2,_E)+_L;A+=int.to_bytes(len(B),2,_E)+B.encode(_a);A+=b'\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\xaa\xaa\x00\x1d\x00';A+=b'\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00\x0e\x00\x0c\x02';A+=b'h2\x08http/1.1\x00\x05\x00\x05\x01\x00\x00\x00\x00';A+=b'\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06';A+=b'\x06\x01\x02\x01\x00\x12\x00\x00\x003\x00+\x00)\xaa\xaa\x00\x01\x00\x00';A+=b'\x1d\x00 '+gen_x25519_public_key();A+=b'\x00-\x00\x02\x01\x01\x00+\x00\x0b\n\xba\xba\x03\x04\x03\x03\x03\x02\x03';A+=b'\x01\x00\x1b\x00\x03\x02\x00\x02::\x00\x01\x00\x00\x15';A+=int.to_bytes(517-len(A)-2,2,_E);A+=_L*(517-len(A));return bytes(A)
async def get_encrypted_cert(host,port,server_name):
	async def A(reader):
		A=reader
		try:
			B=(await A.readexactly(1))[0];C=await A.readexactly(2)
			if C!=_Y:return 0,_F
			D=int.from_bytes(await A.readexactly(2),_E);E=await A.readexactly(D);return B,E
		except asyncio.IncompleteReadError:return 0,_F
	B,C=await asyncio.open_connection(host,port);C.write(gen_tls_client_hello_msg(server_name));await C.drain();E,K=await A(B)
	if E!=22:return _F
	F,L=await A(B)
	if F!=20:return _F
	G,D=await A(B)
	if G!=23:return _F
	if len(D)<MIN_CERT_LEN:
		H,I=await A(B)
		if H!=23:return _F
		J=('The MASK_HOST %s sent some TLS record before certificate record, this makes the '+'proxy more detectable')%config.MASK_HOST;print_err(J);return I
	return D
async def get_mask_host_cert_len():
	global fake_cert_len;B=10;C=60
	while _A:
		try:
			if not config.MASK:await asyncio.sleep(C);continue
			D=get_encrypted_cert(config.MASK_HOST,config.MASK_PORT,config.TLS_DOMAIN);A=await asyncio.wait_for(D,timeout=B)
			if A:
				if len(A)<MIN_CERT_LEN:E='The MASK_HOST %s returned several TLS records, this is not supported'%config.MASK_HOST;print_err(E)
				elif len(A)!=fake_cert_len:fake_cert_len=len(A);print_err('Got cert from the MASK_HOST %s, its length is %d'%(config.MASK_HOST,fake_cert_len))
			else:print_err('The MASK_HOST %s is not TLS 1.3 host, this is not recommended'%config.MASK_HOST)
		except ConnectionRefusedError:print_err('The MASK_HOST %s is refusing connections, this is not recommended'%config.MASK_HOST)
		except(TimeoutError,asyncio.TimeoutError):print_err('Got timeout while getting TLS handshake from MASK_HOST %s'%config.MASK_HOST)
		except Exception as F:print_err('Failed to connect to MASK_HOST %s: %s'%(config.MASK_HOST,F))
		await asyncio.sleep(config.GET_CERT_LEN_PERIOD)
async def get_srv_time():
	E=_A0;F=30;global disable_middle_proxy;global is_time_skewed;B=_B
	while _A:
		try:
			G,I=await make_https_req(E)
			for A in G.split(b'\r\n'):
				if not A.startswith(b'Date: '):continue
				A=A[len('Date: '):].decode();C=datetime.datetime.strptime(A,'%a, %d %b %Y %H:%M:%S %Z');D=datetime.datetime.utcnow();is_time_skewed=(D-C).total_seconds()>F
				if is_time_skewed and config.USE_MIDDLE_PROXY and not disable_middle_proxy:print_err('Time skew detected, please set the clock');print_err('Server time:',C,'your time:',D);print_err('Disabling advertising to continue serving');print_err('Putting down the shields against replay attacks');disable_middle_proxy=_A;B=_A
				elif not is_time_skewed and B:print_err('Time is ok, reenabling advertising');disable_middle_proxy=_B;B=_B
		except Exception as H:print_err('Error getting server time',H)
		await asyncio.sleep(config.GET_TIME_PERIOD)
async def clear_ip_resolving_cache():
	global mask_host_cached_ip;A=myrandom.randrange(60-10,60+10);B=myrandom.randrange(120-10,120+10)
	while _A:mask_host_cached_ip=_C;await asyncio.sleep(myrandom.randrange(A,B))
async def update_middle_proxy_info():
	async def C(url):
		F=re.compile('proxy_for\\s+(-?\\d+)\\s+(.+):(\\d+)\\s*;');C={};H,G=await make_https_req(url);E=F.findall(G.decode('utf8'))
		if E:
			for(B,A,D)in E:
				if A.startswith('[')and A.endswith(']'):A=A[1:-1]
				B,D=int(B),int(D)
				if B not in C:C[B]=[(A,D)]
				else:C[B].append((A,D))
		return C
	F='https://core.telegram.org/getProxyConfig';G='https://core.telegram.org/getProxyConfigV6';H=_A0;global TG_MIDDLE_PROXIES_V4;global TG_MIDDLE_PROXIES_V6;global PROXY_SECRET
	while _A:
		try:
			D=await C(F)
			if not D:raise Exception('no proxy data')
			TG_MIDDLE_PROXIES_V4=D
		except Exception as A:print_err('Error updating middle proxy list:',A)
		try:
			E=await C(G)
			if not E:raise Exception('no proxy data (ipv6)')
			TG_MIDDLE_PROXIES_V6=E
		except Exception as A:print_err('Error updating middle proxy list for IPv6:',A)
		try:
			I,B=await make_https_req(H)
			if not B:raise Exception('no secret')
			if B!=PROXY_SECRET:PROXY_SECRET=B;print_err('Middle proxy secret updated')
		except Exception as A:print_err('Error updating middle proxy secret, using old',A)
		await asyncio.sleep(config.PROXY_INFO_UPDATE_PERIOD)
def init_ip_info():
	global my_ip_info;global disable_middle_proxy
	def A(url):
		B=5
		try:
			with urllib.request.urlopen(url,timeout=B)as A:
				if A.status!=200:raise Exception('Invalid status code')
				return A.read().decode().strip()
		except Exception:return
	B='http://v4.ident.me/';C='http://ipv4.icanhazip.com/';D='http://v6.ident.me/';E='http://ipv6.icanhazip.com/';my_ip_info[_M]=A(B)or A(C);my_ip_info[_H]=A(D)or A(E)
	if my_ip_info[_H]and _N not in my_ip_info[_H]:my_ip_info[_H]=_C
	if my_ip_info[_H]and(config.PREFER_IPV6 or not my_ip_info[_M]):print_err('IPv6 found, using it for external communication')
	if config.USE_MIDDLE_PROXY:
		if not my_ip_info[_M]and not my_ip_info[_H]:print_err('Failed to determine your ip, advertising disabled');disable_middle_proxy=_A
def print_tg_info():
	N='{}: {}';M='link';L='tg://proxy?{}';K='secret';J='port';I='server';global my_ip_info;global proxy_links;E=_B
	if config.PORT==3256:
		print('The default port 3256 is used, this is not recommended',flush=_A)
		if not config.MODES[_G]and not config.MODES[_I]:print('Since you have TLS only mode enabled the best port is 443',flush=_A)
		E=_A
	if not config.MY_DOMAIN:
		F=[A for A in my_ip_info.values()if A]
		if not F:F=['YOUR_IP']
	else:F=[config.MY_DOMAIN]
	proxy_links=[]
	for(A,B)in sorted(config.USERS.items(),key=lambda x:x[0]):
		for G in F:
			if config.MODES[_G]:C={I:G,J:config.PORT,K:B};D=urllib.parse.urlencode(C,safe=_N);O=L.format(D);proxy_links.append({_T:A,M:O});print(N.format(A,O),flush=_A)
			if config.MODES[_I]:C={I:G,J:config.PORT,K:'dd'+B};D=urllib.parse.urlencode(C,safe=_N);P=L.format(D);proxy_links.append({_T:A,M:P});print(N.format(A,P),flush=_A)
			if config.MODES[_J]:R='ee'+B+config.TLS_DOMAIN.encode().hex();C={I:G,J:config.PORT,K:R};D=urllib.parse.urlencode(C,safe=_N);Q=L.format(D);proxy_links.append({_T:A,M:Q});print(N.format(A,Q),flush=_A)
		if B in[_l,'0123456789abcdef0123456789abcdef','00000000000000000000000000000001']:H='The default secret {} is used, this is not recommended'.format(B);print(H,flush=_A);S=''.join(myrandom.choice('0123456789abcdef')for A in range(32));print('You can change it to this random secret:',S,flush=_A);E=_A
	if config.TLS_DOMAIN==_m:print('The default TLS_DOMAIN www.google.com is used, this is not recommended',flush=_A);H='You should use random existing domain instead, bad clients are proxied there';print(H,flush=_A);E=_A
	if E:print_err('Warning: one or more default settings detected')
def setup_files_limit():
	try:import resource as A;C,B=A.getrlimit(A.RLIMIT_NOFILE);A.setrlimit(A.RLIMIT_NOFILE,(B,B))
	except(ValueError,OSError):print('Failed to increase the limit of opened files',flush=_A,file=sys.stderr)
	except ImportError:pass
def setup_asyncio():asyncio.constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES=100
def setup_signals():
	if hasattr(signal,'SIGUSR1'):
		def A(signum,frame):import pdb;pdb.set_trace()
		signal.signal(signal.SIGUSR1,A)
	if hasattr(signal,'SIGUSR2'):
		def B(signum,frame):init_config();ensure_users_in_user_stats();apply_upstream_proxy_settings();print('Config reloaded',flush=_A,file=sys.stderr);print_tg_info()
		signal.signal(signal.SIGUSR2,B)
def try_setup_uvloop():
	if config.SOCKS5_HOST and config.SOCKS5_PORT:return
	try:import uvloop as A;asyncio.set_event_loop_policy(A.EventLoopPolicy());print_err('Found uvloop, using it for optimal performance')
	except ImportError:pass
def remove_unix_socket(path):
	try:
		if stat.S_ISSOCK(os.stat(path).st_mode):os.unlink(path)
	except(FileNotFoundError,NotADirectoryError):pass
def loop_exception_handler(loop,context):
	C=context;A=C.get('exception');B=C.get('transport')
	if A:
		if isinstance(A,TimeoutError):
			if B:B.abort();return
		if isinstance(A,OSError):
			D={10038,121};E={113}
			if A.errno in D:return
			elif A.errno in E:
				if B:B.abort();return
	loop.default_exception_handler(C)
def create_servers(loop):
	C=loop;B=[];D=hasattr(socket,'SO_REUSEPORT');E=hasattr(socket,'AF_UNIX')
	if config.LISTEN_ADDR_IPV4:A=asyncio.start_server(handle_client_wrapper,config.LISTEN_ADDR_IPV4,config.PORT,limit=get_to_tg_bufsize(),reuse_port=D);B.append(C.run_until_complete(A))
	if config.LISTEN_ADDR_IPV6 and socket.has_ipv6:A=asyncio.start_server(handle_client_wrapper,config.LISTEN_ADDR_IPV6,config.PORT,limit=get_to_tg_bufsize(),reuse_port=D);B.append(C.run_until_complete(A))
	if config.LISTEN_UNIX_SOCK and E:remove_unix_socket(config.LISTEN_UNIX_SOCK);A=asyncio.start_unix_server(handle_client_wrapper,config.LISTEN_UNIX_SOCK,limit=get_to_tg_bufsize());B.append(C.run_until_complete(A));os.chmod(config.LISTEN_UNIX_SOCK,438)
	if config.METRICS_PORT is not _C:
		if config.METRICS_LISTEN_ADDR_IPV4:A=asyncio.start_server(handle_metrics,config.METRICS_LISTEN_ADDR_IPV4,config.METRICS_PORT);B.append(C.run_until_complete(A))
		if config.METRICS_LISTEN_ADDR_IPV6 and socket.has_ipv6:A=asyncio.start_server(handle_metrics,config.METRICS_LISTEN_ADDR_IPV6,config.METRICS_PORT);B.append(C.run_until_complete(A))
	return B
def create_utilitary_tasks(loop):
	B=loop;A=[];C=asyncio.Task(stats_printer(),loop=B);A.append(C)
	if config.USE_MIDDLE_PROXY:
		D=asyncio.Task(update_middle_proxy_info(),loop=B);A.append(D)
		if config.GET_TIME_PERIOD:E=asyncio.Task(get_srv_time(),loop=B);A.append(E)
	F=asyncio.Task(get_mask_host_cert_len(),loop=B);A.append(F);G=asyncio.Task(clear_ip_resolving_cache(),loop=B);A.append(G);return A
def main():
	init_config();ensure_users_in_user_stats();apply_upstream_proxy_settings();init_ip_info();print_tg_info();setup_asyncio();setup_files_limit();setup_signals();try_setup_uvloop();init_proxy_start_time()
	if sys.platform=='win32':A=asyncio.ProactorEventLoop()
	else:A=asyncio.new_event_loop()
	asyncio.set_event_loop(A);A.set_exception_handler(loop_exception_handler);E=create_utilitary_tasks(A)
	for B in E:asyncio.ensure_future(B)
	F=create_servers(A)
	try:A.run_forever()
	except KeyboardInterrupt:pass
	if hasattr(asyncio,'all_tasks'):C=asyncio.all_tasks(A)
	else:C=asyncio.Task.all_tasks(A)
	for B in C:B.cancel()
	for D in F:D.close();A.run_until_complete(D.wait_closed())
	G=hasattr(socket,'AF_UNIX')
	if config.LISTEN_UNIX_SOCK and G:remove_unix_socket(config.LISTEN_UNIX_SOCK)
	A.close()
if __name__=='__main__':main()