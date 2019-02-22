import paramiko
hostname = ""
remote_conn_pre = ''
remote_conn = '' 

#can be used to start up a paramiko ssh session with a device
def sshconnect(ip,username,password):
	global remote_conn_pre
	global remote_conn
	#initialize paramiko SSH client
	remote_conn_pre = paramiko.SSHClient() 
	#------------------------------------------------------------------
	#if the SSH key presented by the server is not yet known, ignore warnings and add it to client 
	remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
	#------------------------------------------------------------------
	#open connection to the device
	remote_conn_pre.connect(ip,username=username,password=password,look_for_keys=False,allow_agent=False)
	#------------------------------------------------------------------
	#invoke a shell object to send commands once SSH session is established
	remote_conn = remote_conn_pre.invoke_shell() 
	return remote_conn
	#------------------------------------------------------------------
#------------------------------------------------------------------

#can be used to gather the cisco device's hostname
def getciscohostname(ip,username,password):
	global hostname
	global remote_conn_pre
	global remote_conn
	#initialize paramiko SSH client
	remote_conn_pre = paramiko.SSHClient() 
	#------------------------------------------------------------------
	#if the SSH key presented by the server is not yet known, ignore warnings and add it to client 
	remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
	#------------------------------------------------------------------
	#open connection to the device
	remote_conn_pre.connect(ip,username=username,password=password,look_for_keys=False,allow_agent=False)
	#------------------------------------------------------------------
	#invoke a shell object to send commands once SSH session is established
	remote_conn = remote_conn_pre.invoke_shell() 
	#------------------------------------------------------------------
    #gathering hostname from first few bits of SSH session
	hostname = remote_conn.recv(5000)
	hostname = hostname.replace("#","")
	hostname = hostname.replace(">","")
	hostname = hostname.replace("\n","")
	#------------------------------------------------------------------
#------------------------------------------------------------------