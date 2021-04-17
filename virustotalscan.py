import os
import time
import json
import xml.etree.ElementTree as ET
from virus_total_apis import PublicApi as VirusTotalPublicApi


def check():
    os.system('cmd /c "autorunsc.exe -v -h -x * > autoruns.xml"')
    # -h will create hash


def cycle(cycletime):
    print("The next cycle will begin in ")
    i = int(cycletime)
    while i > 0:
        print(i)
        time.sleep(1)
        i -= 1


def main():
    API_KEY = 'Enter your virus total api here!!'
    virustotal = VirusTotalPublicApi(API_KEY)
    cycletime = input("Please enter how frequently (in seconds) you wish to make the check : \n")
    while True:
        flag = False
        check()
        #tree = ET.parse('autoruns.xml')
        tree = ET.parse('autorunsExample.xml')
        print("Those are the virustotal check results:")
        for item in tree.findall('item'):
            vt_detection = item.find('vt-detection').text
            if vt_detection[0] != '0':
                flag = True
            checkit = item.find('md5hash').text
            result = virustotal.get_file_report(checkit)
            print(result)
        if flag:
            print("Possible malicious programs that have been detected :")
        for item in tree.findall('item'):
            vt_detection = item.find('vt-detection').text

            if vt_detection[0] != '0':
                flag = True
                name = item.find('itemname').text
                location = item.find('location').text
                hyperlink = item.find('vt-permalink').text
                print("The malicious file name is: ", name)
                print("The location of the malicious file is: ", location)
                print("A Link to Virustotal detection : ", hyperlink, "\n")
        if flag is False:
            print("No viruses detected on this scan , AMAZING !! ")

        cycle(cycletime)


if __name__ == "__main__":
    main()


