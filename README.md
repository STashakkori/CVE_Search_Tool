# CVE_Search_Tool
This is a Rust applet that searches a local .xml CVE database for entries based on entry number. Enjoy

Download a .XML of the CVE here from MITRE:
https://cve.mitre.org/data/downloads/index.html

Then you can use this tool to search it. Just pass it an entry number and let it work. Returns nothing if not found

Also, there is an unsafe block in this code that grabs bytes from the .xml file without checking them for valid
UTF-8. Don't worry too much about it. If you grab the database directly from MITRE likely valid

![image](https://github.com/STashakkori/CVE_Search_Tool/assets/4257899/9711d557-85ee-4410-bd3b-443cba4f0dcf)
