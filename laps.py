#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse
from datetime import datetime
parser = argparse.ArgumentParser(description='Dump LAPS Passwords')
parser.add_argument('-u','--username',  help='username for LDAP', required=True)
parser.add_argument('-p','--password',  help='password for LDAP (or LM:NT hash)',required=True)
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)
parser.add_argument('-o','--output', help='Output file to CSV', required=False)


def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]


def main():
    # Get the current runtime for logging purposes
    getTime = datetime.now()
    runtime = getTime.strftime("%m-%d-%Y %H:%M:%S") 
    print("LAPS Dumper - Running at " + runtime)
    
    args = parser.parse_args()
    #Check if the user specifies a file output. If so, it creates a new CSV.
    if args.output != None:
        filename = args.output + getTime.strftime("-%m-%d-%Y.csv")
        f = open(filename,'w')
        header = ['Computer,Password,Expiration Time,Epoch Expiration Time,Query Time\n']
        f.writelines(header)
        f.close()

    if args.ldapserver:
        s = Server(args.ldapserver, get_info=ALL)
    else:
        s = Server(args.domain, get_info=ALL)
    c = Connection(s, user=args.domain + "\\" + args.username, password=args.password, authentication=NTLM, auto_bind=True)
    try:
    	c.search(search_base=base_creator(args.domain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','ms-Mcs-AdmPwdExpirationTime','cn'])
    	for entry in c.entries:
            print (str(entry['cn']) +" "+ str(entry['ms-Mcs-AdmPwd']))
            #Appends the Machine Name (not Machine Account) + Password + Password Expiration + Epoch (for some reason it wouldn't convert HMS correctly, so I opted for perserving the epoch in logs) + Runtime to the csv.
            if args.output != None:
                epoch = (int(str(entry['ms-Mcs-AdmPwdExpirationTime']))/10000000) - 11644473600
                convertedTime = datetime.fromtimestamp(epoch).strftime("%m-%d-%Y")
                f = open(filename,'a')
                f.writelines(str(entry['cn'])+",\""+ str(entry['ms-Mcs-AdmPwd']) + "\"," + convertedTime + "," + str(epoch) + "," + runtime +"\n")
                f.close()
    except Exception as ex:
    	if ex.args[0] == "invalid attribute type ms-MCS-AdmPwd":
    		print("This domain does not have LAPS configured")
    	else:
    		print(ex)
    	
if __name__ == "__main__":
    main()
