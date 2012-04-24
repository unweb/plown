#!/usr/bin/python

import sys, os, re, time
from optparse import OptionParser
import threading
import urllib2, urllib

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

#tested with python 2.4, 2.6, 2.7
description="""Plown is a security scanner tool for Plone CMS.
Although Plone has the best security track record of any major CMS and is considered highly secure, misconfigurations 
and weak passwords might enable system break-ins. 
Plown has been developed to ease the discovery of usernames and passwords, 
and act as an assistant to system administrators to strengthen their Plone sites.
"""

usage = '''Usage:
  %s [-b for Brute Force mode] [-U userslist] [-P passlist] [-T threads] [-l login_form url] target
EXAMPLES:
  Enumeration mode
  plown.py http://localhost
  plown.py http://localhost:8081/Plone

  Brute Force mode
  plown.py -b -U userfile -P passfile http://site.com
  plown.py -b -U userfile -P passfile -T 30 http://site.com
    ''' % sys.argv[0]

__version__ = "0.2"
__url__ = "https://unweb.me/projects/open-source/plown"
__copyright__ = "Unweb.me"
__license__ = "GPL"
__author__ = "provetza"
__author_email__ = "provetza@unweb.me"

headers = { 'User-Agent' : "Plown %s security tool" % __version__ }


#dict with vulnerabilities.Entries like the following:
#VULNERABILITIES_DICT['Plone Hotfix number or CVE'] = [buggy_url, buggy scenario, hotfix_URL, message]

VULNERABILITIES = {
    '20110622': ['/acl_users/getUsers','credentials_cookie_auth', \
        'http://plone.org/products/plone-hotfix/releases/20110622', ''],
    'CVE-2006-4247': ['/portal_password_reset/requestReset?userid=admin', \
        'credentials_cookie_auth', 'http://plone.org/products/plone/security/advisories/cve-2006-4247', ''],
    '20110928': ['/portal_modifier/modules/StandardModifiers', 'credentials_cookie_auth', \
        'http://plone.org/products/plone-hotfix/releases/20110928', 'This bug affects Plone 4.0.x series <= 4.0.9, 4.1(.0), 4.2 <= 4.2a2.']
}


class BruteForcer(threading.Thread):
    "Handles the threading stuff"
    def __init__(self, username, password, target):
        super(BruteForcer, self).__init__()

        self.target   = target
        self.password = password
        self.username     = username


    def run(self):
        try_pair(self.target, self.username, self.password)


def url_open(url):
    "Helper function for opening urls"
    try:
        request = urllib2.Request(url, headers=headers)
        handle = urllib2.build_opener()
    except IOError:
        return None
    return (request, handle)

def normalize_url(url):
    "adds http in url and strips ending slash"
    if not 'http' in url:
        url = 'http://%s' % url
    if url.endswith('/'):
        url = url[:-1]

    request, handle = url_open(url)
    print ("\nStarting Plown version %s (%s)") % (__version__, __url__)
    print ("Plown report for %s") % url
    try:
        content = unicode(handle.open(request).read(), "utf-8", errors="replace")
    except urllib2.HTTPError:
        print ("Url not found")
        sys.exit(0)
    except: 
        print ("Failed to resolve target hostname/IP")
        sys.exit(0)
    return url


def find_vulnerabilities(target):
    "Provided a list with known Plone vulnerabilities, try to discover if site is vulnerable"

    for vuln_num, vuln in VULNERABILITIES.items():
        url = target + vuln[0]
        request, handle = url_open(url)   
        try:
            content = handle.open(request)
            if not vuln[1] in content.geturl():
                print ("[*] %s seems to be vulnerable to bug %s. Please visit %s and apply the hotfix, or upgrade to the latest Plone version. %s") \
     % (target, vuln_num, vuln[2], vuln[3])
        except Exception, e: 
            pass


def find_usernames(target):
    """try to get a list with usernames by asking portal_membership.
        There are other urls as well that expose usernames, and also the Creator attribute
        on objects. A future version will include a crawler and ask for the Creator of objects. 
     """
    usernames = []
    content = ''
    url = target + "/portal_membership/searchForMembers"
    request, handle = url_open(url)   
    try:
        content = unicode(handle.open(request).read(), "utf-8", errors="replace")
    except Exception, e: 
        print ("Could not find any usernames")
    if content:
        usernames.extend(re.findall(r"<PloneUser '([\w.]*)", content))
        usernames.extend(re.findall(r"/portal_memberdata/([\w]*) used for", content))
        if usernames:
            if len(usernames) > 30:
                print ("[*] found %s usernames. Saving on file userslist") % len(usernames)
                try:
                    f = open('userslist', 'w')
                    f.write(', '.join(usernames))
                    f.close()
                except:
                    print ("Something has happened and file with usernames was not saved")
            else:
                print ("[*] found %s usernames: %s") % (len(usernames), ' '.join(usernames))
        else:
            print ("Could not find usernames")


def try_pair(target, username, password):
    "Try to authenticate on a Plone form, using a pair of user/password"
    url = target
    values = {'__ac_name' : username,
              '__ac_password' : password,
              'came_from':'', 
              'form.submitted':1
             }

    data = urllib.urlencode(values)
    try:
        req = urllib2.Request(url, data, headers=headers)
        response = urllib2.urlopen(req)
        if '__ac' in response.headers['set-cookie']: 
            global pairs_found
            pairs_found[username]=password
    except Exception, e:
        pass

def makelist(file):
    '''
    Helper function that makes lists out of a comma separated file
    '''
    words = []

    try:
        fd = open(file, 'r')
    except IOError:
        print ("unable to read file %s") % file
        sys.exit(-1)        

    except Exception, e:
        print ("unknown error")
        sys.exit(-1)

    for line in fd.readlines(): #should be: admin,markos,nikos...
        word = line.replace('\n', '').split(',')
        words.extend(word)

    words = [word.replace(' ','') for word in words if word]
    return words
 

def main():
    """Plown main function. Handles options specified and runs on Enumeration and Brute force modes 
    """

    parser = OptionParser(description=description, version=__version__ )

    parser.add_option("-b", "--bruteforce",
                  action="store_true", dest="mode", default=False, help="Brute Force mode")

    parser.add_option('-U', dest='userlist', help='comma seperated userlist file')

    parser.add_option('-P', dest='passlist', help='comma separated passwordlist file')

    parser.add_option('-l', action='store', dest='login_form', default='login_form',\
        help='login form url, if different than on default plone (login_form)')

    parser.add_option('-T', type='int', dest='threads', default=16, \
        help='number of connections in parallel (%default threads)')

    (options, args) = parser.parse_args()

    try:
        target = normalize_url(args[0])
    except IndexError:   
	    print ("Plown version %s (%s) \n") % (__version__,__url__)
	    print ("Target host is missing")
	    print (usage)
	    sys.exit(-1)

    users = options.userlist
    passwords = options.passlist
    threads = options.threads

    global mode
    if options.mode:
        mode = 'Brute Force'
    else:
        mode = 'Enumeration'

    if mode == 'Enumeration':
        print ("%s mode, searching for usernames") % mode
        find_usernames(target)
        find_vulnerabilities(target)

    if mode == 'Brute Force':
        print ("%s mode, searching for valid username/password pairs") % mode
        userlist = makelist(users)
        passwordlist = makelist(passwords)
        print ("[*] %s user(s) loaded.") % str(len(userlist))
        print ("[*] %s password(s) loaded.") % str(len(passwordlist))

        login_target = target + '/' + options.login_form

        results = []
        tcounter = 0
        total_threads = len(userlist) * len(passwordlist)
        finished_threads = 0

        global pairs_found
        pairs_found = {}

        print ("[*] Brute Forcing url %s with %s threads") % (login_target, threads)
        for user in userlist:
            for password in passwordlist:
                current = BruteForcer(user, password, login_target)
                results.append(current)
                current.start()
                tcounter += 1
                if tcounter == threads:
                    finished_threads += tcounter
                    sys.stdout.write('\rfinished %s threads. Remaining: %s. Pairs found: %s'  % \
                        (finished_threads, total_threads-finished_threads, len(pairs_found)))
                    for result in results:
                        result.join()
                    tcounter = 0


        for thread in threading.enumerate():
           if thread.isAlive():
               time.sleep(5)
               #if thread is running give it a few seconds to terminate

        if pairs_found:   
            print ("\n[*] found %s pairs") % len(pairs_found)
            for user, password in pairs_found.items(): print ("  %s:%s") % (user, password)
        else:
            print ("\nNo valid pairs are found")


if __name__ == "__main__":
    #if in brute force mode and ctrl+c pressed, show valid pairs (if any)
    try:
        main()
    except KeyboardInterrupt:
        if mode == 'Brute Force':
            print ("\n[*] found %s pairs") % len(pairs_found)
            for user, password in pairs_found.items(): print ("  %s:%s") % (user, password)            
        print ("Ctrl+c pressed, exiting")
        sys.exit(0)
