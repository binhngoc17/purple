import httplib2
import os
import base64
import requests
import json
from rfc3987 import parse

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools

try:
	import argparse
	flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
	flags = None

SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Gmail API Quickstart'


def get_credentials():
	"""Gets valid user credentials from storage.

	If nothing has been stored, or if the stored credentials are invalid,
	the OAuth2 flow is completed to obtain the new credentials.

	Returns:
		Credentials, the obtained credential.
	"""
	home_dir = os.path.expanduser('~')
	credential_dir = os.path.join(home_dir, '.credentials')
	if not os.path.exists(credential_dir):
		os.makedirs(credential_dir)
	credential_path = os.path.join(credential_dir,
								   'gmail-quickstart.json')

	store = oauth2client.file.Storage(credential_path)
	credentials = store.get()
	if not credentials or credentials.invalid:
		flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
		flow.user_agent = APPLICATION_NAME
		if flags:
			credentials = tools.run_flow(flow, store, flags)
		else: # Needed only for compatability with Python 2.6
			credentials = tools.run(flow, store)
		print 'Storing credentials to ' + credential_path
	return credentials

def main():
	"""Shows basic usage of the Gmail API.

	Creates a Gmail API service object and outputs a list of label names
	of the user's Gmail account.
	"""
	credentials = get_credentials()
	http = credentials.authorize(httplib2.Http())
	service = discovery.build('gmail', 'v1', http=http)

	# results = service.users().labels().list(userId='me').execute()
	# labels = results.get('labels', [])
	results = service.users().messages().list(userId='me').execute()
	messages = results.get('messages', [])
	latest = requests.get(
		'http://mpa-hack.tendtoinfinity.com/api/messages/latest',
	)
	latest_msg_id = latest.json()['id']

	data = []
	if not messages:
		print 'No message found'
	else:
		for message in messages:
			if message['id'] <= latest_msg_id:
				break
			msg = get_msg('me', message['id'])
			requests.post(
				'http://mpa-hack.tendtoinfinity.com/api/messages',
				data=json.dumps(msg),
				headers={'Content-Type': 'application/json'},
			)
			data.append(msg)

	for item in data:
		print item

def get_msg(user_id, message_id):
	credentials = get_credentials()
	http = credentials.authorize(httplib2.Http())
	service = discovery.build('gmail', 'v1', http=http)
	msg = service.users().messages().get(userId=user_id, id=message_id, format='full').execute()
	try:
		content = msg['payload']['parts'][0]['body']['data']
	except:
		content = msg['payload']['parts'][0]['parts'][0]['body']['data']

	content = base64.urlsafe_b64decode(content.encode('UTF-8'))
	try:
		res = parse(content.strip()	, rule='IRI')
		resp = requests.post(
			'http://ocr.tendtoinfinity.com/ocr',
			data=json.dumps({
				'img_url': content.strip(),
				'engine': 'tesseract'
			})
		)
		content = resp.text
	except:
		pass

	resp = {
		'attachments': [],
		'content': content,
		'id': message_id,
	}

	for d in msg['payload']['headers']:
		if d['name'] == 'From':
			resp['from'] = d['value']
		if d['name'] == 'Subject':
			resp['subject'] = d['value']
		if d['name'] == 'To':
			resp['to'] = d['value']

	for part in msg['payload']['parts']:
		  if part['filename']:	
		  	if part['mimeType'] == 'text/csv':
				attachment = service.users().messages().attachments().get(
					userId=user_id, messageId=message_id, id=part['body']['attachmentId']).execute()
				attachment = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
				resp['attachments'] = resp['attachments'] + process_attachment(attachment)
	return resp

def process_attachment(att):
	lines = att.split('\n')
	keys = lines[0].split(',')
	records = []
	for line in lines[1:-1]:
		record = {}
		vals = line.split(',')
		i = 0
		for val in vals:
			record[keys[i]] = val
			i += 1
		records.append(record)
	return records

if __name__ == '__main__':
	main()
