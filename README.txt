0) The user must use a Gmail desktop client to send a list of domain names each one in a separate line. All extra text must be deleted before sending the email to a preconfigured gmail mailbox that's accessed by the python script via Gmail API.

1) The "_pull_and_process_domains_from_Gmail_message.py" will access the mailbox and search for messages satisfying a given search query (specified in the _config.json file)

2) Once queried messages are listed, it checks a given text file for previously processed messages and skips them

3) If an unprocessed message is found, it executes 3 links each one starting a python analysis script. One via VirusTotal, one via Urlvoid and one via Quttera.

4) Then it continuously checks the task list for these newly started python scripts. Once they have terminated it resumes by sending their result as emails to the sender

5) The first email that is sent contains domain names that have been flagged as dangerous by VirusTotal, Urlvoid or Quttera 

6) The other 3 messages each contains the analysis details for the queried websites


For google gmail api follow: https://developers.google.com/gmail/api/quickstart/python

According to your python version start the following command : C:\Program Files\Python[version]\Scripts>pip install --upgrade google-api-python-client oauth2client

To exploit WMI download the right package from and install it:  https://pypi.org/project/WMI/#files

In Order for the scripts to work you need to modify the .lnk file properties to add your own 'starts in' path

Also, decompress the "Triage_Scripts" zip archive into the root directory

In Addition to that, make sure you fill in the _config.json file with the appropriate information

Finally make sure your token.json file and credantials.json file are available in the root folder following your first script execution (Google will prompt for validation via browser)

Warning: 

1) This script only works if you have these prerequisites:

- All the import libraries that are not natively available with python have been downloaded and installed such as: wmi, requests, lxml and google-api-python-client
- You run it in the Windows OS

2)  Don't abuse these scripts to overload or misuse the websites

3) Respect the rate limits of each website. In the provided scripts, explicit rate limits have been implemented.