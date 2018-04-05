 
 
 
    Hashcat-based automated WPA cracker server for Windows 


*** Installation ***

* Install Python 3.x (www.python.org).
* Install flask:
	* Open a command prompt
	* Type 'pip install flask'
* Pick a directory (say, c:\wpa_server). Copy everything into this directory.
* Copy a complete hashcat tree into its subdirectory. Edit the HASHCAT_TREE entry in config.txt to match the correct path. 
E.g., your layout could look like this

c:\wpa_server
c:\wpa_server\config.txt
c:\wpa_server\wpa_server.py
c:\wpa_server\do_hashcat.py
c:\wpa_server\templates\status.html
c:\wpa_server\static\index.html
c:\wpa_server\hashcat-3.50\hashcat64.exe

* If you use an external app (e.g. MSI Afterburner) to control GPU fans, edit config.txt and change the GPU_TEMP_DISABLE setting to true.

* If your hashcat is 3.50 or newer, edit config.txt and set HCCAPX_V4 to true.

* Edit wordlists.txt.sample to use your preferred wordlists, masks, rules, etc. By default, it assumes that there's a 'c:\wpa_server\[hashcat directory]\rockyou.txt' and it uses that file as a wordlist. 


*** Initialization ***

Open a command prompt, change into the install directory and type:

set FLASK_APP=wpa_server.py
flask run --host=0.0.0.0

(This would ideally be done under a restricted-privilege account, for security purposes. Run as administrator at your own risk.)

In a browser, open the url "http://127.0.0.1:5000". You should see a page that says:

Current status: Idle

followed by the list of entries in your hashcat.potfile.

Do the same on another computer in the same network, this time typing "http://x.x.x.x:5000" where x.x.x.x is the IP address of the server. (Type 'ipconfig' to find it quickly, it typically starts with 192.168.)

If the page loads correctly, you're good to go. If not, go to Windows firewall settings on the server and open port 5000 and retry.

Back on the server, open another command prompt, again in the install directory, and run do_hashcat.py. Keep both command prompt windows open.

*** Usage ***

To see the current status of the server, or to retrieve any keys it successfully cracked, simply go to http://x.x.x.x:5000.

To start a new job, go to http://x.x.x.x:5000/upload. You will see two buttons, "Browse" and "Send the file". Click on "Browse", select one or more .cap files produced with aircrack-ng, and then click "Send". They will be automatically uploaded, parsed and queued. 

Alternatively, copy the script helpers/upload_v2.py (Python 2.x) or helpers/upload_v3.py (Python 3.x) (currently broken) to the capture machine and use it to upload directly, bypassing the browser:

python upload_v2.py 192.168.1.101 grabs-01.cap grabs-02.cap grabs-03.cap

(substitute the actual IP address for 192.168.1.101)

*** Customization ***

Editing 'wordlists.txt' allows you to add custom search masks or to vary the analysis depending on the SSID or the vendor of the AP.

Each row in the file corresponds to a single invocation of hashcat. It consists of several tab-delimited fields:
Name: a unique identifier of the wordlist, used internally to keep track of previously attempted hccapx/wordlist combinations.
Condition: determines whether the wordlist will be used. Possible options:
	'*': always on
	'ssid=xxxx': use only if the SSID matches the pattern 'xxxx'. Standard regex rules apply. E.g. ssid=NETGEAR.. would match any SSID starting with NETGEAR followed by exactly two
	 symbols. ssid=NETGEAR\d\d would match if the SSID consists of the word NETGEAR and two digits. ssid=NETGEAR.* would match if the SSID consists of the word NETGEAR following by
	 zero or more arbitrary symbols.
	'oui=xxxx': use only if the OUI (the first six letters of the MAC address) matches the pattern. Likewise, regex rules apply.
	'vendor=xxxx': use only if the vendor matches the pattern. See oui.txt for the list of vendors.
Mode: a single digit, passed with '-a' as a command-line option to hashcat. E.g. 0 for a straight wordlist, 1 for a combinator attack, or 3 for a mask.
Parameters: these are going to be passed to hashcat as-is.

Rows are arranged in the order of decreasing priority. The script will attempt every hccapx with the first entry in the list, then with the second entry, etc. until it runs out of jobs. (At that point, it'll go to sleep, checking for new work periodically.) Put short jobs near the front, and move multi-hour wordlists and masks to the end.

The script autogenerates a few wordlists to assist with cracking every time it tries to launch hashcat, and corresponding entries are included in wordlists.txt.sample.
* 'known_passwords.txt' is the list of all passwords in the potfile (should be checked first thing to avoid reduplication of effort)
* 'temp.dict' and 'temp2.dict' are lists of substrings of the SSID with varying capitalizations.

*** Limitations *** 

The server treats handshakes as distinct as long as either the AP or the station differ. In other words, if you upload two handshakes for the same AP but with different stations, the server will try to crack both independently. That is inefficient and usually undesirable.

The server is not guaranteed to be watertight security-wise. Adding authentication is on the todo list.

