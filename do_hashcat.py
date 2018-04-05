import os, time, subprocess, re
from threading import Timer


def do_spawn_hashcat(a,x,y,z):
	global hashcat_dir
	v=['.\\hashcat64.exe', '--gpu-temp-disable','-m', '2500', '-w', '3', '-a', a, '../' + x]
	if type(y) is list:
		v+=y
	else:
		v.append(y)
	of=open("hashcat_status.txt", "w")
	of.write(x+'\t'+z)
	of.close()
	print('Launching hashcat with args', v, 'in', hashcat_dir, os.getcwd())
	#v=['hashcat64.exe']
	subprocess.run(args=v, cwd=hashcat_dir,shell=True)
	os.unlink("hashcat_status.txt")
	
f=open("config.txt","r").readlines()
f=[x.replace('\n','').split('=',1) for x in f]
f=[x for x in f if len(x)==2]

hashcat_dir='hashcat-3.30\\'
for x in f:
	if x[0]=='HASHCAT_TREE':
		hashcat_dir=x[1]
		if hashcat_dir[-1]!='/' and hashcat_dir[-1]!='\\':
			hashcat_dir+='\\'


ouis=open('oui.txt','r').readlines()
ouis=[x.strip() for x in ouis]
ouis=[x.split('\t',1) for x in ouis]

rule_list=open('wordlists.txt', 'r').readlines()
rules=[]


for n in range(0, len(rule_list)):
	x=rule_list[n].split('\t')
	name=x[0]
	condition=x[1]
	if '=' in condition:
		condition=condition.split('=',1)
	x=x[2:]
#	condition2=None
#	if x[0][:3]=='oui' or x[0][:4]=='ssid' or x[0][:6]=='vendor':
#		condition2=x[0]
#		x=x[1:]
	mode=x[0]
	args=x[1:]
	rules.append((name, n, condition, mode, args))

def lookup_oui(x):
	x=x.upper()
	x=x[:6]
	for y in ouis:
		if y[0]==x:
			return y[1]
	return None

def pull_ssid(x):
	ssid=x
	ssid=ssid.replace('\\','')
	ssid=ssid.split('.')
	if len(ssid)<4:
		return None
	else:
		return ssid[-4]

def gen_ssid_lists(ssid):
	if ssid==None:
		return
	perms1=[ssid[x:y]+'\n' for x in range(0,len(ssid)) for y in range(x+3, len(ssid))]
	ssid_l=ssid.lower()
	ssid_u=ssid.upper()
	ssid2=ssid_l[0:1].upper()+ssid_l[1:]
	perms2=[ssid_l[x:y]+'\n' for x in range(0,len(ssid)) for y in range(x+3, len(ssid))]
	perms3=[ssid_u[x:y]+'\n' for x in range(0,len(ssid)) for y in range(x+3, len(ssid))]
	perms4=[ssid2[x:y]+'\n' for x in range(0,len(ssid)) for y in range(x+3, len(ssid))]

	list1=list(set(perms1))
	list2=list(set(perms1+perms2+perms3+perms4))
	list1=[x for x in list1 if len(x)<8 or len(x)==len(ssid)]
	list2=[x for x in list2 if len(x)<8 or len(x)==len(ssid)]

	of=open('temp.dict','w')
	of.writelines(list1)
	of.close()
	of=open('temp2.dict','w')
	of.writelines(list2)
	of.close()

def test_rule(ap, rule):
	if type(rule) is str:
		if rule=='*':
			return True
		print('Can\'t parse the rule ', rule)
		exit(-1)
	if rule[0]=='oui':
		return re.fullmatch(rule[1], ap[0][:6].upper())!=None
	if rule[0]=='vendor':
		return re.fullmatch(rule[1], ap[2])!=None
	if rule[0]=='ssid':
		if ap[3]==None:
			return False
		return re.fullmatch(rule[1], ap[3])!=None
	print('Can\'t parse the rule ', rule)
	exit(-1)

def timer_func():
	try:
		os.unlink("hashcat_status.txt")
	except:
		pass
	aps=[]
	try:
		am=open("ap_map.txt", "r")
		aps=am.readlines()
		aps=[x.replace('\n','').split('\t') for x in aps]
		aps=[(x[0], x[1], lookup_oui(x[0]), pull_ssid(x[1])) for x in aps]
		am.close()
	except:
		pass
	done_aps=[]
	try:
		ad=open("ap_done.txt", "r")
		done_aps=ad.readlines()
		done_aps=[x.replace('\n','').split('\t') for x in done_aps]
		ad.close()
		#print(done_aps)
	except:
		pass
	for r in rules:
		for x in aps:
			if not test_rule(x, r[2]):
				print('file ', x, 'rule ', r, 'Not applicable')
				continue
			if [x[1], r[0]] in done_aps:
				print('file ', x, 'rule ', r, 'Done')
				continue

			f=open(hashcat_dir+'hashcat.potfile','r')
			e=f.readlines()
			f.close()
			e=[x.split(':',2) for x in e]
			of=open(hashcat_dir+'known_passwords.txt','w')
			of.writelines([x[2] for x in e if len(x)>=3])
			of.close()
			gen_ssid_lists(x[3])
			do_spawn_hashcat(r[3], x[1], r[4], x[0])
			ad=open("ap_done.txt", "a")
			ad.write(x[1]+'\t'+r[0]+'\n')
			ad.close()

while True:
	timer_func()
	time.sleep(5.0)