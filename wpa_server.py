from flask import Flask, request, render_template
import io, os, tempfile, subprocess


conf=open("config.txt","r").readlines()
conf=[x.replace('\n','').split('=',1) for x in conf]
conf=[x for x in conf if len(x)==2]
hashcat_dir='hashcat-3.30\\'
for x in conf:
	if x[0]=='HASHCAT_TREE':
		hashcat_dir=x[1]
		if hashcat_dir[-1]!='/' and hashcat_dir[-1]!='\\':
			hashcat_dir+='\\'



use_v4=False
for x in conf:
	if x[0]=='HCCAPX_V4' and x[1].lower()=='true':
		use_v4=True

def tempfilename():
	tf=tempfile.NamedTemporaryFile()
	nm=tf.name
	tf.close()
	return nm


def do_post():
	global use_v4
	resp=''
	tfs=[]
	print(request.files.getlist("myFile"))
	fl=request.files.getlist("myFile")
	logtf=tempfilename()
	outtf='ap_map.txt'
	outdir='.'
	parser='cap_parse.exe'
	for x in fl:
		nm=tempfilename()
		x.save(nm)
		tfs.append(nm)
		f=open(nm,'rb')
		f.seek(0,os.SEEK_END)
		d=f.tell()
		f.close()
		print(x, d)
		resp+=str(d)+' '+nm+'<br>'
		print(parser, nm, logtf, outdir, outtf)
		if use_v4:
			os.spawnv(os.P_WAIT, parser, [parser, nm, logtf, outdir, outtf, "v4"])
		else:
			os.spawnv(os.P_WAIT, parser, [parser, nm, logtf, outdir, outtf])
		os.unlink(nm)
	log_file=open(logtf, 'r')
	logdata='<br>'.join(log_file.readlines())
	log_file.close()
	out_file=open(outtf, 'r')
	outdata='<br>'.join(out_file.readlines())
	out_file.close()
	return 'Uploaded successfully'
#	return logdata+'<br>'+outdata

app = Flask(__name__,static_url_path='')

@app.route('/')
def get_status():
	state='Idle'
	try:
		f=open("hashcat_status.txt", "r")
		state=f.readline()
		state='Processing ' + state
		f.close()
	except:
		pass

	f=open(conf + 'hashcat.potfile','r')
	e=f.readlines()
	f.close()
	e=[x.split(':')[1:3] for x in e]
	return render_template('status.html', state=state, data=e)
	
@app.route('/upload', methods=['GET', 'POST'])
def upload():
	if request.method=='POST':
		return do_post()
	else:
		return app.send_static_file('index.html')
		