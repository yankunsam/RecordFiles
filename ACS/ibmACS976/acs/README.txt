$Id: README.txt 963 2017-03-15 20:37:25Z kgoldman $
Written by Ken Goldman
IBM Thomas J. Watson Research Center

json note
---------

The distros can't seem to decide whether the json include directory is
/usr/include/json or /usr/include/json-c.

I use /usr/include/json.  If your distro uses json-c, just make a soft link:

# cd /usr/include
# ln -s json-c json


RHEL Install Libraries
-----------------

mysql
mysql-devel
openssl
openssl-devel		(tested with 1.0.x, not tested with 1.1.x)
json-c
json-c-devel
php
php-devel
php-mysql


# service mysqld start
# service httpd start

Centos and recent Fedora
------------------------

# yum install mariadb
# yum install mariadb-server
# systemctl start mariadb.service
# systemctl enable mariadb.service

Ubuntu
------

apache2
php, php5-dev, php-mysql	for the web demos
libjson-c3, libjson-c-dev

Install the Database Schema
---------------------------

As root:

# mysql
mysql> create database tpm2;
mysql> grant all privileges on tpm2.* to ''@'localhost';

As non-root:

> mysql -D tpm2 < dbinit.sql

Build Libraries and Applications
--------------------------------

1 - If using a SW TPM

https://sourceforge.net/projects/ibmswtpm2/

> cd .../tpm2/src
> make

2 - TSS and utilities:  creates libtss.so

https://sourceforge.net/projects/ibmtpm20tss/

> cd .../tpm2/utils
> make

3 - Attestation demo

# mkdir /var/www/html/acs
# chown user /var/www/html/acs
# chgrp user /var/www/html/acs
# chmod 777  /var/www/html/acs

> cd .../tpm2/acs
> make

	The makefile assumes that the TSS library libtss.so is in
	../utils and makes a link.  If the TSS is installed somewhere
	else, either copy libtss.so here or make a link to it.



Provision the RSA EK Certificate CA Signing Key
-----------------------------------------------

*** This optional step is only required if changing the endorsement
    key CA signing key cakey.pem / cacert.pem included in the package.

*** This is done once per software install.  

*** This is only required when using a SW TPM.

1 - Create an EK certificate server CA signing key

> cd .../tpm2/acs
> openssl genrsa -out cakey.pem -aes256 -passout pass:rrrr 2048

2 - Create a self signed EK root CA certificate

> openssl req -new -x509 -key cakey.pem -out cacert.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK CA         
Email Address []:

3 - View the certificate for correctness.  

> openssl x509 -text -in cacert.pem -noout

Issuer and subject should match.  Validity 20 years.  Etc.

4 - Install the cacert.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.

The HW TPM vendor root certificates should already be there.

Provision the EC EK Certificate CA Signing Key
----------------------------------------------

*** This optional step is only required if changing the endorsement
    key CA signing key cakeyecc.pem / cacertecc.pem included in the
    package.

*** This optional step requires at least openssl 1.0.2. 1.0.1 will not
    work.

> openssl genpkey -out cakeyecc.pem -outform PEM -pass pass:rrrr -aes256 -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve

2 - Create a self signed EK root CA certificate

> openssl req -new -x509 -key cakeyecc.pem -out cacertecc.pem -days 3650

Country Name (2 letter code) [XX]:US
State or Province Name (full name) []:NY
Locality Name (eg, city) [Default City]:Yorktown
Organization Name (eg, company) [Default Company Ltd]:IBM
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:EK EC CA         
Email Address []:

3 - View the certificate for correctness.  

openssl x509 -text -in cacertecc.pem -noout

Issuer and subject should match.  Validity 20 years.  Etc.

4 - Install the cacert.pem in the directory where the HW TPM root
certificates are.  Currently, that's .../tpm2/utils/certificates.


SW TPM Provisioning
-------------------

*** This is only required for a SW TPM.  HW TPMs come with EK
    certificates.

*** This is only required once per TPM.  It is installed in SW TPM
    non-volatile memory.

1 - Start the SW TPM

.../tpm2/src> tpm_server
.../tpm2/utils> powerup;startup

2 - Provision the SW TPM with EK certificates

(RSA public key and CA key)

.../tpm2/acs> clientek -alg rsa -cakey cakey.pem -capwd rrrr -v

(EC public key and CA key)

.../tpm2/acs> clientek -alg ec -cakey cakeyecc.pem -capwd rrrr -caalg ec -v

CAUTION.  The EK and certificate will normally persist.  However,
running the TSS regression test rolls the EPS (endorsement hierarchy
primary seed), voiding everything.  You can reprovision and re-enroll,
but it's easier to make a copy of the SW TPM NV space now, and restore
it as necessary.

> cd .../tpm2/src
> cp NVChip NVChip.save

Provisioning the server
-----------------------

*** This is only required if changing privacy CA signing key
pcakey.pem/ pcacert.pem  included in the package.

1 - Create a privacy CA signing key

> cd .../tpm2/acs
> openssl genrsa -out pcakey.pem -aes256 -passout pass:rrrr 2048

2 - Create a self signed privacy CA certificate

> openssl req -new -x509 -key pcakey.pem -out pcacert.pem -days 3560

Use AK CA as the common name

3 - View the certificate for correctness.  

> openssl x509 -text -in pcacert.pem -noout

Start the server
----------------

1 - The server uses a TPM as a crypto coprocessor.  It must point to a
different (typically a software) TPM and TSS data directory.

A - If the server is being run on the same machine as the client:

> cd .../tpm2/acs
	for example
> export TPM_DATA_DIR=/gsa/yktgsa/home/k/g/kgold/tpm2
	or
> setenv TPM_DATA_DIR /gsa/yktgsa/home/k/g/kgold/tpm2

B - If the server is being run on a different machine from the client:

> .../tpm2/src/tpm_server
> .../tpm2/utils/powerup
> .../tpm2/utils/startup

2 - Edit the file .../tpm2/utils/certificates/rootcerts.txt 

Change the path name to wherever the directory is installed.


4 - Set the server port

setenv ACS_PORT	2323

4 - Start the attestation server.  

E.g., 

> server -v -root ../utils/certificates/rootcerts.txt >! serverenroll.log4j

-v and piping to a file are optional.

Client Setup
-------------

Set the TSS environment variables (e.g. TPM_INTERFACE_TYPE) if a
client HW TPM is being used.  See the TSS docs.

Provisioning a Client
---------------------

NOTE: With a hardware TPM, this can take several minutes, and appear
to hang.  Creating a primary key on a hardware TPM is a long calculation.

This installs the client attestation key certificate at the
attestation server.

> clientenroll -alg rsa -v -ho cainl.watson.ibm.com >! clientenroll.log4j

or a different machine with EC

> clientenroll -alg ec -v -ho cainl.watson.ibm.com -ma cainlec.watson.ibm.com >! clientenroll.log4j

where -ho is the hostname of the server, and is optional for
localhost.

-v and piping to a file are optional.


Running an Attestation
----------------------

*** One time per client reboot, if the client does not have an event
log (and none do today), and the PCRs are uninitialized, extend the
test event log tpm2bios.log into the TPM PCRs.  If the firmware has
already extended the PCRs, the event log will not match.

tpm2bios.log is a sample event log.

> .../utils/eventextend -if tpm2bios.log -v >! b.log4j

imasig.log is a sample IMA log

> .../utils/imaextend -if imasig.log -le -v > ! i.log4j

As often as desired, run an attestation.

> client -alg rsa -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v >! client.log4j

or 

> client -alg ec -ifb tpm2bios.log -ifi imasig.log -ho cainl.watson.ibm.com -v -ma cainlec.watson.ibm.com >! client.log4j

where -ho is the hostname of the server, and is optional for
localhost.

Code Structure
--------------

The client side are separated into the main client and clientenroll
executables and a clientlocal set of utilities.

The structure permits the client and clientenroll functions to be run
in a different space (perhaps a VM) than the (clientlocal) space that
has the TPM.  An interface would have to be provided to pass the
function parameters through.

Minimal TSS
-----------

For a client with a minimal local client environment, build a seperate
minimal TSS.

> cd .../utils

To run with a HW TPM on a platform with no socket library, add to CCFLAGS  
	-DTPM_NOSOCKET
	
create the minimal TSS for the ACS first, then the fill TSS for the utilities

> make -f makefile.min clean all
> make clean all

build the ACS against the minimal TSS

> cd .../acs

build the server and the test code against the full TSS

> make clean server clientek tpm2pem

build the client code against the minimal TSS

> make -f makefile.min clean all

Clearing a hostname for testing
-------------------------------

delete from machines where hostname = 'cainl.watson.ibm.com';
delete from attestlog where hostname = 'cainl.watson.ibm.com';
delete from imalog where hostname = 'cainl.watson.ibm.com';



Database Tables
---------------

machines - all machines

	id - primary key for machine
	hostname - typically the fully qualified domain name, untrusted	
	tpmvendor - TPM manufacturer name,  untrusted
	ekcertificatepem - endorsement key certificate, pem format
	ekcertificatetext - endorsement certificate, dump
	akcertificatepem - attestation key certificate, pem format
	akcertificatetext - attestation certificate, dump
	enrolled - date of attestation key enrollment
	imaevents - next IMA event to be processed
		set to zero on enrollment
		set back to zero on first quote or reboot
	imapcr - value corresponding to imaevents, used for incremental update		
	boottime - last boot time,  untrusted, 
		whatever the client provides
	pcr00-pcr23 - sha1 and sha256, white list, values from first valid quote
	valid - certificate is valid

attestlog - all attestations for all machines

	id - primary key for attestation
	userid - userid of attestation, untrusted
		whatever the client provides
	hostname - typically the fully qualified domain name, untrusted, 
		whatever the client provides
	boottime - last boot time, untrusted, 
		whatever the client provides
	timestamp - date  of attestation
	nonce - freshness nonce
	pcrselect - which PCRs are selected, currently hard coded to 0-23
	quote - quote data in json, for debug and forensics
	pcr00-pcr23 - current value from quote
	pcrschanged - boolean flag, pcrs changed from last attestation
	quoteverified - boolean flag, signature over quote data is valid
	logverified - boolean flag, bios event log verifies against its PCRs
	logentries - number of entries in BIOS event log
	imaevents - number of entries in IMA event log
	pcrinvalid - boolean flag, pcrs different from white list
	imaver -  boolean flag, IMA event log verifies against its PCR
	badimalog - boolean flag, IMA event log is malformed

imalog - current IMA event log for all machines

	id - primary key for attestation
	hostname - typically the fully qualified domain name, untrusted, 
		whatever the client provides
	boottime - last boot time,  untrusted, 
		whatever the client provides
	timestamp - server time of attestation
	entrynum - ima event number
	ima_entry - the raw ima event as hex ascii
	filename - ima event file name
	badevent - if the template data hash did not verify, or the template data could not be
		unmarshaled
	nosig - if the template data lacked a signature
	nokey - if the key referenced by the template data is unknown
	badsig - if the BIOS entry signature did not verify

bioslog - current BIOS event log for all machines
	id - primary key for attestation
	hostname - typically the fully qualified domain name, untrusted, 
		whatever the client provides
	timestamp - server time of attestation
	entrynum - bios event number	
	bios_entry - the raw ima event as hex ascii
	eventtype - TCG_PCR_EVENT2.eventType as ascii
	event - TCG_PCR_EVENT2.event as ascii

At enroll
	machines insert
		hostname 
		tpmvendor
		ekcertificatepem
		ekcertificatetext
		akcertificatepem
		akcertificatetext
		valid			false, then true

		pcrnn			null
		imaevents		null
		imapcr			null
	
At nonce
	attestlog insert
		userid
		hostname
		timestamp
		nonce
		pcrselect

		quoteverified		null
		pcrnn			null
		quote			null
		pcrinvalid		null 
		logverified		null
		logentries		null
		imaver			null 
		badimalog		null 


At quote
	machines update

		if quote verified
			if storePcrWhiteList 
				pcrnn
			if storePcrWhiteList or new boottime
				imaevents	0
				imapcr		00...00
			boottime

	atestlog update
		if quote verified
			pcrchanged
			pcrnn
		if !storePcrWhiteList 
			pcrinvalid 
		quoteverified
		quote
		boottime
		

At BIOS

	
	atestlog update
		logverified 
		logentries 

At IMA
		
	machines update
		if ima pcr verified
			imaevents		last event for incremental
			imapcr			current PCR value
		
	atestlog update
		badimalog 
		imaver 			
		imaevents			last event for this quote
