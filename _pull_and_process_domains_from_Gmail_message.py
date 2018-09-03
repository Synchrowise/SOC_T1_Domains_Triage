"""Get a list of Messages from the user's mailbox.
"""
#Baseline libraries for Gmail API requests
from __future__ import print_function
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

#libraries for querieing the json config file
import json

#Libraries for error handling
from apiclient import errors

#Additional libraries to get messages
import base64
import email

#Libraries to execute .bat with Python
from subprocess import Popen

#Libraries to manipulate os objects
import os

#Libraries to check last modification tim of a folder
import glob

#Libraries to query os via wmi
import wmi

#Libraries to manage time and pause process
import time
import datetime

#Libraries to manipulate files and folder on a high level
import shutil
from shutil import copyfile

#Important libraries for defining new MIME message with attachments and for guessing MIME type based on file name extension
#https://docs.python.org/3.3/library/email-examples.html
import mimetypes
from optparse import OptionParser
from email.mime.multipart import MIMEMultipart
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from email import encoders

#Defining the privilege scope of this application when accessing yout gmail mailbox. The scope used here is the maximal scope
SCOPES = 'https://mail.google.com/'



def	copy_last_modified_folder (folder):
	
	#Detect the last modified folder within the given "folder"
	last_modified_folder = max(glob.glob(os.path.join(folder, '*/')), key=os.path.getmtime)
	last_modified_folder = last_modified_folder[:-1]
	
	#Copy the name of the detected folder so that we can create a new folder with the same name in the script root directory
	last_modified_folder_copied = last_modified_folder[last_modified_folder.find("\\")+1:]
	
	#Copy the content of the last modified folder within "folder" into a newly created folder in the script root directory
	shutil.copytree(last_modified_folder,last_modified_folder_copied)
	
	return last_modified_folder_copied
		
	
	
def send_message(service, user_id, message):

	try:
		message = (service.users().messages().send(userId=user_id, body=message)
					   .execute())
		print ('Message Id: %s\n' % message['id'])
		return message
	except errors.HttpError as error:
		print ('An error occurred: %s\n' % error)

def create_message_with_attachment(
    sender, to, subject, message_text, file):

	message = MIMEMultipart()
	message['to'] = to
	message['from'] = sender
	message['subject'] = subject

	msg = MIMEText(message_text)
	message.attach(msg)

	content_type, encoding = mimetypes.guess_type(file)

	if content_type is None or encoding is not None:
		content_type = 'application/octet-stream'

	main_type, sub_type = content_type.split('/', 1)
	if main_type == 'text':
		fp = open(file, 'rb')
		msg = MIMEText(fp.read(), _subtype=sub_type)
		fp.close()
	elif main_type == 'image':
		fp = open(file, 'rb')
		msg = MIMEImage(fp.read(), _subtype=sub_type)
		fp.close()
	elif main_type == 'audio':
		fp = open(file, 'rb')
		msg = MIMEAudio(fp.read(), _subtype=sub_type)
		fp.close()
	else:
		fp = open(file, 'rb')
		msg = MIMEBase(main_type, sub_type)
		msg.set_payload(fp.read())
		fp.close()
		# Encode the payload using Base64: https://docs.python.org/3.3/library/email-examples.html
		encoders.encode_base64(msg)
		
	filename = os.path.basename(file)
	msg.add_header('Content-Disposition', 'attachment', filename=filename)
	
	message.attach(msg)

	#because we use python 3 we add .encode('ASCII') https://www.reddit.com/r/AskProgramming/comments/64sjmj/gmail_api_error_from_code_sample_a_byteslike/
	#return {'raw': base64.urlsafe_b64encode(message.as_string().encode('ASCII'))}
	#return {'raw': base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}
	#https://github.com/google/google-api-python-client/issues/93
	
	raw = base64.urlsafe_b64encode(message.as_bytes())
	raw = raw.decode()
	return {'raw': raw}
	
	
def create_folder(folder_name):	
	if not os.path.exists(folder_name):
		os.makedirs(folder_name)
	else:
		print("The folder to be created already exists\n")

def	CheckProcessedMessages (message_ID):
	
	check = False
	
	for line in open("processed_messages.txt","r"):
		if	line.find(message_ID) != -1:
			check = True
			break
	
	return check
		
	
def	CheckNumberOfPythonProcesses ():
	procs = wmi.WMI ()
	p=0
	for proc in procs.Win32_Process ():
		if str(proc.Name) == 'python.exe':
			p=p+1
	
	return p


def EmptyTextFiles (directory):

	for text_file in os.listdir(directory):
		if text_file.endswith(".txt"):
			open(directory+"/"+text_file, 'r+').truncate(0)
			#Truncate works even if the file is already open
	

def GetMimeMessage(service, user_id, msg_id):

	try:
		message = service.users().messages().get(userId=user_id, id=msg_id,
                                             format='raw').execute()

		print ('Message snippet: %s' % message['snippet'])

		msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))

		mime_msg = email.message_from_string(msg_str)

		return mime_msg
		
	except errors.HttpError as error:
		print ('An error occurred: %s' % error)

def GetAttachments(service, user_id, msg_id, store_dir):

	try:
		message = service.users().messages().get(userId=user_id, id=msg_id).execute()

		
		
		
		for part in message['payload']['parts']:
			if part['filename']:
				
				file_data = base64.urlsafe_b64decode(part['body']['data']
                                             .encode('UTF-8'))

				path = ''.join([store_dir, part['filename']])

				f = open(path, 'w')
				f.write(file_data)
				f.close()
		
	except errors.HttpError as error:
		print ('An error occurred: %s' % error)
		

def GetMessage(service, user_id, msg_id):

	try:
		message = service.users().messages().get(userId=user_id, id=msg_id).execute()


		return message
		
	except errors.HttpError as error:
		print ('An error occurred: %s' % error)

def ListMessagesMatchingQuery(service, user_id, query='',includeSpam=False):
#https://developers.google.com/gmail/api/v1/reference/users/messages/list#examples
	try:
		response = service.users().messages().list(userId=user_id,
													q=query,includeSpamTrash=includeSpam).execute()
		messages = []
		if 'messages' in response:
			messages.extend(response['messages'])

		while 'nextPageToken' in response:
			page_token = response['nextPageToken']
			response = service.users().messages().list(userId=user_id,
													q=query,
													pageToken=page_token,includeSpamTrash=includeSpam).execute()
			messages.extend(response['messages'])

		return messages
	except errors.HttpError as error:
		print ('An error occurred: %s' % error)

def main():

	#Open the json config file
	with open('_config.json') as json_data_file:
		config = json.load(json_data_file)
		
	
	store = file.Storage(config["gmail"]["token"]) #Adding reference to your gmail token file via config file
	creds = store.get()
	if not creds or creds.invalid:
		flow = client.flow_from_clientsecrets(config["gmail"]["secrets"], SCOPES)#Adding reference to your gmail credantials file via config file
		creds = tools.run_flow(flow, store)
	
	service = build('gmail', 'v1', http=creds.authorize(Http()))

	user_id= config["gmail"]["user_id"] #Adding reference to you Gmail Email Address via config file
	query=config["gmail"]["query"] #Adding reference to your mailbox search query via config file
	
	includeSpam = True
	
	while (True):
	
		try:
		
			messages_list = ListMessagesMatchingQuery(service,user_id,query,includeSpam)
			
			print("Messages filtered by given request are the following:\n"+ str(messages_list)+"\n" )
			
			i = 0
			
			print("The number of messages coming from the specifid senders is: "+str(len(messages_list))+"\n")
			while(i<len(messages_list)):
				
				print("We will now check the message with index number: "+str(i))
				
				First_message_id = messages_list[i]['id']
				
				First_message_id_string = str(First_message_id)
				
				if (CheckProcessedMessages (First_message_id_string)):
					print("The following message has already been proceessed: "+First_message_id_string+"\n")
					
				else:
					print("New unprocessed message Found: "+First_message_id_string+" ! Starting domains triage scripts for this message...\n")
				
					Firt_message_content = GetMessage(service, user_id, First_message_id)
					
					
					
					#save message data. This is optionnal
					open("data.txt","a").write (str(Firt_message_content)+"\n\n")
								
					#Detect the sender
					message_content_string=str(Firt_message_content)
					detect_sender=message_content_string[message_content_string.find("smtp.mailfrom="):]
					detect_sender=detect_sender[detect_sender.find("=")+1:]
					
									
					
					
					if detect_sender.find("gmail.com") != -1:
						detect_sender=detect_sender[:-(len(detect_sender)-detect_sender.find("'"))]
						detect_sender=detect_sender[:-(len(detect_sender)-detect_sender.find(";"))]
						
											
						if 'data' in Firt_message_content['payload']['body']:
							test_chunk = Firt_message_content['payload']['body']['data']
							print("base64 data is the following: "+test_chunk+"\n\n")
							chunk = str(base64.urlsafe_b64decode(Firt_message_content['payload']['body']['data']))
							chunk = chunk.replace("\\r\\n","\n").replace("b'","").replace("\n'","")
							
						else:
							print("Domains triage request is coming from Gmail mobile Application!\n")
							test_chunk = Firt_message_content['payload']['parts'][1]['body']['data']
							print("base64 data is the following:  "+test_chunk+"\n\n")
							chunk = str(base64.urlsafe_b64decode(Firt_message_content['payload']['parts'][1]['body']['data']))
							
							print("Decoded base64 data is the following:  "+chunk+"\n\n")
							
							chunk = chunk.replace("\\r\\n'","").replace("b'","").replace("<div dir=\"auto\"><a href=\"http://","\n")
												
							chunk = chunk[1:]
							
							open("domains.txt","w").write(chunk)
							
							chunk=""
							
							for line_ in open("domains.txt","r"):
								line_=line_[:-(len(line_)-line_.find("\""))]
								chunk= chunk+line_+"\n"
								
							chunk = chunk[:-1]
							
									
					else:
						print("Message not from gmail domain\n\n")
						
					
					print("Sender is: "+detect_sender+"\n")
					
					#Write domains from email body into domains.txt file of root directory
					f=open("domains.txt","w")
					f.write(chunk)
					f.close()
					
					
					#Empty text files of triage directories 
					EmptyTextFiles ("Filter_domains_by_VT_API")
					EmptyTextFiles ("Filter_domains_by_Urlvoid_API")
					EmptyTextFiles ("Filter_domains_by_quttera")
					
					#Declare file objects of domains.txt file related to triage directories
					f_VT=open("Filter_domains_by_VT_API/domains.txt","w")
					f_URLVOID=open("Filter_domains_by_Urlvoid_API/domains.txt","w")
					f_QUTTERA=open("Filter_domains_by_quttera/domains.txt","w")
					
					#Write into and Close domains.txt files of triage directories
					f_VT.write(chunk)
					f_VT.close()
					f_URLVOID.write(chunk)
					f_URLVOID.close()
					f_QUTTERA.write(chunk)
					f_QUTTERA.close()
					
					
					#Start Analysis
					#https://stackoverflow.com/questions/34737206/how-to-launch-a-windows-shortcut-using-python
					os.startfile ("Urlvoid_scan_DOMAINS.lnk")
					os.startfile ("Quttera_scan_DOMAINS.lnk")
					os.startfile ("VT_scan_DOMAINS.lnk")
					
					#save start time
					start_time=str(datetime.datetime.now())[:-7]
					
					while CheckNumberOfPythonProcesses () > 1 :
						print("\tTriage scripts still running...")
						time.sleep(120)
					
					print ("\nTriage Scripts are no longer running! Analysis Complete!\n")
					
					
					#Copy and past last modified folder in each triage folder into the scrip root directory
					VT_folder = copy_last_modified_folder('Filter_domains_by_VT_API')
					os.rename(VT_folder, "_"+VT_folder)
					Urlvoid_folder = copy_last_modified_folder('Filter_domains_by_Urlvoid_API')
					os.rename(Urlvoid_folder, "_"+Urlvoid_folder)
					quttera_folder = copy_last_modified_folder('Filter_domains_by_quttera')
					os.rename(quttera_folder, "_"+quttera_folder)
					
					VT_folder = "_"+VT_folder
					Urlvoid_folder = "_"+Urlvoid_folder
					quttera_folder = "_"+quttera_folder
					
					#zip each copied folder
					shutil.make_archive("_VT_scan_ID_"+First_message_id_string, 'zip', VT_folder)
					shutil.make_archive("_Urlvoid_scan_ID_"+First_message_id_string, 'zip', Urlvoid_folder)
					shutil.make_archive("_quttera_scan_ID_"+First_message_id_string, 'zip', quttera_folder)
					
					
					#Create messages
					
					new_VT_Scan_message=create_message_with_attachment('Script Messenger', detect_sender, 'Your VT Scan Request '+First_message_id_string, "Please find attached the scan results", "_VT_scan_ID_"+First_message_id_string+".zip")
					new_Urlvoid_Scan_message=create_message_with_attachment('Script Messenger', detect_sender, 'Your Urlvoid Scan Request '+First_message_id_string, "Please find attached the scan results", "_Urlvoid_scan_ID_"+First_message_id_string+".zip")
					new_quttera_Scan_message=create_message_with_attachment('Script Messenger', detect_sender, 'Your quttera Scan Request '+First_message_id_string, "Please find attached the scan results", "_quttera_scan_ID_"+First_message_id_string+".zip")
					
					
					print("Sleeping 60 seconds as time to upload Analysis files...\n")
					time.sleep(60)
					
					#Create file with unique positive/blacklisted/Suspicious domain names to send to user to analyse with more priority
					count=0
					total=0
					
					open("aggregated_positives.txt","a").write("--------------"+str(datetime.datetime.now())[:-7]+" - Request ID: "+First_message_id_string+" results below--------------\n")
					for line in open('domains.txt','r'):
						total=total+1
						if (line in open(VT_folder+"/positives.txt",'r') or line in open(Urlvoid_folder+"/positives.txt",'r') or line in open(quttera_folder+"/blacklisted.txt",'r') or line in  open(quttera_folder+"/malware.txt",'r') or line in open(quttera_folder+"/suspicious.txt",'r') ):
							open("aggregated_positives.txt","a").write(line)
							count=count+1
					
					
					
					#Create message containing the aggregated positives
					email_subject = "Request ID: "+First_message_id_string
					email_body    = str(count)+" Domains out of "+str(total)+" have been flagged by VT, Quttera or Urlvoid. They are kindly attached to this email. Please look for your request ID in the attached text file"
					create_folder("_Aggregated_Positives_"+First_message_id_string)
					copyfile('aggregated_positives.txt','_Aggregated_Positives_'+First_message_id_string+'/aggregated_positives.txt')
					shutil.make_archive('_Aggregated_Positives_'+First_message_id_string, 'zip', '_Aggregated_Positives_'+First_message_id_string)
					Aggregated_positives_message=create_message_with_attachment('Script Messenger', detect_sender, email_subject,email_body, '_Aggregated_Positives_'+First_message_id_string+".zip")
					print("Sleeping 30s while attachment is being uploaded...\n")
					time.sleep(30)
					send_message(service, user_id, Aggregated_positives_message)
					
					print("Aggregated positives message sent! Sleeping 15s before starting submission of Scan details...\n")
					time.sleep(15)
					
					send_message(service, user_id, new_VT_Scan_message)
					print("VT Scan Message sent! Sleeping 15 seconds before sending second email...\n")
					time.sleep(15)
					send_message(service, user_id, new_Urlvoid_Scan_message)
					print("Urlvoid Scan Message sent! Sleeping 15 seconds before sending next email...\n")
					time.sleep(15)
					send_message(service, user_id, new_quttera_Scan_message)
					print("Quttera Scan Message sent!\n")
					
					#Save end time
					end_time=str(datetime.datetime.now())[:-7]
										
					#Adding message to list of processed messages with end time
					processed_messages=open("processed_messages.txt","a")
					processed_messages.write (First_message_id_string+";"+start_time+";"+end_time+";"+detect_sender+"\n")
					processed_messages.close()
					
				i=i+1
				
				
			
			print("\nNo new messages to process! Sleeping 5min before checking if there are new messages...\n")
			time.sleep(300)
		except (ConnectionResetError,TimeoutError) as error:
			print ('The following connectivity error occured: %s. Sleeping 5min before checking connection...\n' % error)
			time.sleep(300)
		
if __name__ == '__main__':
	main()