#!/usr/bin/env python3

# shcheck - Security headers check!
# Copyright (C) 2019  meliot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import urllib.request, urllib.error, urllib.parse
import socket
import sys
import ssl
import os
import json
from optparse import OptionParser
from defectdojo_api import defectdojo
import datetime


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Client headers to send to the server during the request.
client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0)\
 Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,\
 application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
 }


# Security headers that should be enabled
sec_headers = {
    'X-XSS-Protection': 'warning',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'warning',
    'Referrer-Policy': 'warning',
    'Feature-Policy': 'warning',
    'Expect-CT': 'info',
}

value_headers =  {
    'Access-Control-Allow-Origin',
    'Access-Control-Allow-Credentials',
    'Content-Type'
}

information_headers = {
    'X-Powered-By',
    'Server'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified'
    'Expires',
    'ETag'
}

headers = {}
json_headers = {}

def banner():
    print()
    print("=======================================================")
    print(" > shcheck.py - meliot.................................")
    print("-------------------------------------------------------")
    print(" Simple tool to check security headers on a webserver ")
    print("=======================================================")
    print()


def colorize(string, alert):
    color = {
        'error':    bcolors.FAIL + string + bcolors.ENDC,
        'warning':  bcolors.WARNING + string + bcolors.ENDC,
        'ok':       bcolors.OKGREEN + string + bcolors.ENDC,
        'info':     bcolors.OKBLUE + string + bcolors.ENDC
    }
    return color[alert] if alert in color else string

def dojoUpdate(safeh, dp, value):
    products = dd.list_products(name_contains=dp)
    product_id = None

    finding = {}

    if 'X-Frame-Options' in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.7 - Include anti clickjacking headers'
            finding['description'] = """
            Clickjacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or link on another page when they were intending to click on the top level page. Thus, the attacker is "hijacking" clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both.
Using a similar technique, keystrokes can also be hijacked. With a carefully crafted combination of stylesheets, iframes, and text boxes, a user can be led to believe they are typing in the password to their email or bank account, but are instead typing into an invisible frame controlled by the attacker.
            """
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Low"
            finding['impact'] = "TEST"
            finding['mitigation'] = "TEST"
            finding['references'] = ""
            finding['cwe'] = 346
            finding['severity_justification'] = ""
    elif "Referrer-Policy" in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.6 - Referrer policy header'
            finding['description'] = """
            Requests made from a document, and for navigations away from that document are associated with a Referer header. While the header can be suppressed for links with the noreferrer link type, authors might wish to control the Referer header more directly for a number of reasons, Privacy A social networking site has a profile page for each of its users, and users add hyperlinks from their profile page to their favorite bands.
The social networking site might not wish to leak the user’s profile URL to the band web sites when other users follow those hyperlinks (because the profile URLs might reveal the identity of the owner of the profile).
Some social networking sites, however, might wish to inform the band web sites that the links originated from the social networking site but not reveal which specific user’s profile contained the links.
Security A web application uses HTTPS and a URLbased session identifier. The web application might wish to link to HTTPS resources on other web sites without leaking the user’s session identifier in the URL.
Alternatively, a web application may use URLs which themselves grant some capability.
Controlling the referrer can help prevent these capability URLs from leaking via referrer headers.
Note that there are other ways for capability URLs to leak, and controlling the referrer is not enough to control all those potential leaks.
Trackback A blog hosted over HTTPS might wish to link to a blog hosted over HTTP and receive trackback links.
            """           
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Medium"
            finding['impact'] = ""
            finding['mitigation'] = "Null"
            finding['references'] = ""
            finding['cwe'] = 116
            finding['severity_justification'] = ""
    elif "charset" in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.1 - Content type headers'
            finding['description'] = """
            Setting the right content headers is important for hardening your applications security, this reduces exposure to driveby download attacks or sites serving user uploaded content that, by clever naming could be treated by MS Internet Explorer as executable or dynamic HTML files and thus can lead to security vulnerabilities.

Test to check
Verify that every HTTP response contains a content type header specifying a safe character set (e.g., UTF-8, ISO 8859-1)
            """
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Low"
            finding['impact'] = ""
            finding['mitigation'] = "Null"
            finding['references'] = ""
            finding['cwe'] = 116
            finding['severity_justification'] = ""
    elif "Strict-Transport" in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.5 - HTTP Strict Transport Security (HSTS)'
            finding['description'] = """
            HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header that browser will prevent any communications from being sent over HTTP to the specified domain and will instead send all communications over HTTPS. It also prevents HTTPS click through prompts on browsers.
HSTS addresses the following threats:

User bookmarks or manually types http://example.com and is subject to a man-in-the-middle attacker. HSTS automatically redirects HTTP requests to HTTPS for the target domain.
Web application that is intended to be purely HTTPS inadvertently contains HTTP links or serves content over HTTP. HSTS automatically redirects HTTP requests to HTTPS for the target domain.
A man-in-the-middle attacker attempts to intercept traffic from a victim user using an invalid certificate and hopes the user will accept the bad certificate. HSTS does not allow a user to override the invalid certificate message
"""
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Medium"
            finding['impact'] = ""
            finding['mitigation'] = "Null"
            finding['references'] = ""
            finding['cwe'] = 116
            finding['severity_justification'] = ""
    elif "X-Content-Type" in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.4 - API responses security headers'
            finding['description'] = """
            There are some security headers which should be properly configured in order to protect some API callbacks against Reflective File Download and other type of injections.
Also check if the API response is dynamic, if user input is reflected in the response. If so, you must validate and encode the input, in order to prevent XSS and Same origin method execution attacks.
            """
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Low"
            finding['impact'] = ""
            finding['mitigation'] = "Null"
            finding['references'] = ""
            finding['cwe'] = 116
            finding['severity_justification'] = ""
    elif "Content-Security-Policy" in safeh:
            finding['title'] = 'ASVS v4.0 - 14.4.3 - Content security policy headers'
            finding['description'] = """
            The main use of the content security policy header is to, detect, report, and reject XSS attacks. The core issue in relation to XSS attacks is the browser's inability to distinguish between a script that's intended to be part of your application, and a script that's been maliciously injected by a thirdparty.
            With the use of CSP(Content Security policy), we can tell the browser which script is safe to execute and which scripts are most likely been injected by an attacker.
            """
            finding['active'] = True
            finding['verified'] = True
            finding['severity'] = "Medium"
            finding['impact'] = ""
            finding['mitigation'] = "Null"
            finding['references'] = ""
            finding['cwe'] = 116
            finding['severity_justification'] = ""

    if products.count() > 0:
        for product in products.data["objects"]:
            product_id = product['id']

    product = dd.get_product(product_id)

    engagements = dd.list_engagements(product_in=[product_id], name_contains="Pentest").data['objects']
    engagement_id = None

    for engagement in engagements:
        if "Pentest" in engagement['name']:
            engagement_id = engagement['id']
  
    if engagement_id is None:
        date_start = datetime.datetime.now().date().strftime('%Y-%m-%d')
        date_end = (datetime.datetime.now().date() + datetime.timedelta(weeks=3)).strftime('%Y-%m-%d')
        engagement_id = dd.create_engagement("Pentest", product_id=product_id, lead_id=1,
                                                     status='In Progress', target_start=date_start,
                                                     target_end=date_end)

    tests = dd.list_tests(engagement_in=engagement_id, name="ASVS").data['objects']
    test_id = None

    for test in tests:
        if "ASVS" in test['test_type']: 
            test_id = test['id']

    # Create test if it not exists
    if test_id is None:
        environment = 3 #prod
        test_types = dd.list_test_types('ASVS').data['objects']
        if test_types:
            # Get the first one that matches. TODO: search if findings are inside
            test_type_key_id = test_types[0]['id']
        else:
            # Create new test_type
            test_type_key_id = dd.create_test_type('ASVS').data
        date_start = datetime.datetime.now().date().strftime('%Y-%m-%d')
        date_end = (datetime.datetime.now().date() + datetime.timedelta(weeks=3)).strftime('%Y-%m-%d')
        test_id = dd.create_test(engagement_id, test_type_key_id, environment, target_start=date_start,
                                         target_end=date_end, percent_complete=None)
    safeh = ""

    # Check if findings with the same title are already created.
    try:
        existing_findings = dd.list_findings(
            product_id_in=product_id,
            test_id_in=test_id,
            title_contains=finding['title'],
            limit=500000
        ).data['objects']
    except Exception as e:
        print('Error getting findings: ' + str(e))
    else:
        # Create new finding if it not exists in current test.
        if not existing_findings:
            print("Creating finding '" + finding['title'] + "'...")
            try:
                dd.create_finding(
                    title=finding['title'],
                    description=finding['description'],
                    cwe=finding['cwe'],
                    date=datetime.datetime.now().date().strftime('%Y-%m-%d'),
                    product_id=product_id,
                    engagement_id=engagement_id,
                    test_id=test_id,
                    user_id=1,
                    severity=finding['severity'],
                    impact=finding['impact'],
                    mitigation=finding['mitigation'],
                    active=finding['active'],
                    verified=finding['verified'],
                    references=finding['references'],
                    build=None,
                    line=0,
                    file_path=None,
                    static_finding=False,
                    dynamic_finding=False,
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    under_review=False,
                    under_defect_review=False,
                    numerical_severity=None,
                    severity_justification=finding['severity_justification']
                )
            except Exception as e:
                print('Error creating finding ' + finding['title'] + ' - ' + str(e))

        # Update finding if it already exists.
        else:
            for existing_finding in existing_findings:
                print("Updating finding '" + finding['title'] + "'...")
                try:
                    dd.set_finding(
                        finding_id=existing_finding['id'],
                        description=finding['description'],
                        product_id=product_id,
                        engagement_id=engagement_id,
                        test_id=test_id,
                        active=finding['active'],
                        verified=finding['verified'],
                        severity=finding['severity'],
                        impact=finding['impact'],
                        mitigation=finding['mitigation'],
                        references=finding['references'],
                        cwe=finding['cwe'],
                        severity_justification=finding['severity_justification']
                    )
                except Exception as e:
                    print('Error updating finding ' + finding['title'] + ' - ' + str(e))




def parse_headers(hdrs):
    global headers
    headers = dict((x,y) for x,y in hdrs)

def append_port(target, port):
    return target[:-1] + ':' + port + '/' \
        if target[-1:] == '/' \
        else target + ':' + port + '/'


def set_proxy(proxy):
    if proxy is None:
        return
    proxyhnd = urllib.request.ProxyHandler({
        'http':  proxy,
        'https': proxy
    })
    opener = urllib.request.build_opener(proxyhnd)
    urllib.request.install_opener(opener)

def get_unsafe_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def normalize(target):
    try:
        if (socket.inet_aton(target)):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass
    finally:
        return target


def print_error(e):
    sys.stdout = sys.__stdout__
    if isinstance(e, ValueError):
        print("Unknown url type")

    if isinstance(e, urllib.error.HTTPError):
            print("[!] URL Returned an HTTP error: {}".format(
                colorize(str(e.code), 'error')))

    if isinstance(e, urllib.error.URLError):
            if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
                print("SSL: Certificate validation error.\nIf you want to \
    ignore it run the program with the \"-d\" option.")
            else:
                print("Target host seems to be unreachable ({})".format(e.reason))

def check_target(target, options):
    '''
    Just put a protocol to a valid IP and check if connection works,
    returning HEAD response
    '''
    # Recover used options
    ssldisabled = options.ssldisabled
    useget = options.useget
    proxy = options.proxy
    response = None

    target = normalize(target)

    try:
        request = urllib.request.Request(target, headers=client_headers)

        # Set method
        method = 'GET' if useget else 'HEAD'
        request.get_method = lambda: method

        # Set proxy
        set_proxy(proxy)
        # Set certificate validation 
        if ssldisabled:
            context = get_unsafe_context()
            response = urllib.request.urlopen(request, timeout=10, context=context)
        else:
            response = urllib.request.urlopen(request, timeout=10)

    except Exception as e:
        print_error(e)
        sys.exit(1)

    if response is not None:
        return response
    print("Couldn't read a response from server.")
    sys.exit(3)


def is_https(target):
    '''
    Check if target support HTTPS for Strict-Transport-Security
    '''
    return target.startswith('https://')


def report(target, safe, unsafe):
    print("-------------------------------------------------------")
    print("[!] Headers analyzed for {}".format(colorize(target, 'info')))
    print("[+] There are {} security headers".format(colorize(str(safe), 'ok')))
    print("[-] There are not {} security headers".format(
        colorize(str(unsafe), 'error')))
    print()

def dojoLogin():
    with open("api.txt", "r") as fp:
        global dd
        user = fp.readline().strip()
        api_key = fp.readline().strip()        
        dd = defectdojo.DefectDojoAPI("https://dojo-ppd.axa-assistance.intraxa/", api_key, user, debug=False, verify_ssl=False)

def main(options, targets):

    #DojoLogin
    dojoLogin()

    # Getting options
    port = options.port
    cookie = options.cookie
    custom_headers = options.custom_headers
    information = options.information
    cache_control = options.cache_control
    hfile = options.hfile
    json_output = options.json_output
    global dp
    dp = options.dp
    
    # Disabling printing if json output is requested
    if json_output:
        global json_headers
        sys.stdout = open(os.devnull, 'w')
    banner()
    # Set a custom port if provided
    if cookie is not None:
        client_headers.update({'Cookie': cookie})
    
    # Set custom headers if provided
    if custom_headers is not None:
        for header in custom_headers:
            # Split supplied string of format 'Header: value'
            header_split = header.split(': ')
            # Add to existing headers using header name and header value
            try:
                client_headers.update({header_split[0]: header_split[1]})
            except IndexError:
                print("[!] Header strings must be of the format 'Header: value'")
                raise SystemExit(1)
    
    if hfile is not None:
        with open(hfile) as f:
            targets = f.read().splitlines()
        


    for target in targets:
        if port is not None:
            target = append_port(target, port)
        
        safe = 0
        unsafe = 0

        # Check if target is valid
        response = check_target(target, options)
        rUrl = response.geturl()

        print("[*] Analyzing headers of {}".format(colorize(target, 'info')))
        print("[*] Effective URL: {}".format(colorize(rUrl, 'info')))
        parse_headers(response.getheaders())
        json_headers["present"] = {}
        json_headers["missing"] = []

        for safeh in sec_headers:
            if safeh in headers:
                safe += 1
                json_headers["present"][safeh] = headers.get(safeh)

                # Taking care of special headers that could have bad values

                # X-XSS-Protection Should be enabled
                if safeh == 'X-XSS-Protection' and headers.get(safeh) == '0':
                    print("[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            colorize(headers.get(safeh), 'warning')))

                # Printing generic message if not specified above
                else:
                    print("[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            headers.get(safeh)))
            else:
                unsafe += 1
                json_headers["missing"].append(safeh)
                # HSTS works obviously only on HTTPS
                if safeh == 'Strict-Transport-Security' and not is_https(rUrl):
                    unsafe -= 1
                    json_headers["missing"].remove(safeh)
                    continue

                print('[!] Missing security header: {}'.format(
                    colorize(safeh, sec_headers.get(safeh))))
                dojoUpdate(safeh, dp, "")

        if information:
            json_headers["information_disclosure"] = {}
            i_chk = False
            print()
            for infoh in information_headers:
                if infoh in headers:
                    json_headers["information_disclosure"][infoh] = headers.get(infoh)
                    i_chk = True
                    print("[!] Possible information disclosure: \
header {} is present! (Value: {})".format(
                            colorize(infoh, 'warning'),
                            headers.get(infoh)))
            if not i_chk:
                print("[*] No information disclosure headers detected")
        

        if cache_control:
            json_headers["caching"] = {}
            c_chk = False
            print()
            for cacheh in cache_headers:
                if cacheh in headers:
                    json_headers["caching"][cacheh] = headers.get(cacheh)
                    c_chk = True
                    print("[!] Cache control header {} is present! \
Value: {})".format(
                            colorize(cacheh, 'info'),
                            headers.get(cacheh)))
            if not c_chk:
                print("[*] No caching headers detected")

        report(rUrl, safe, unsafe)
        if json_output:
            sys.stdout = sys.__stdout__
            json_output = json.loads(str(json_headers).replace("\'", "\""))
            print(json.dumps(json_output))

        ## ADDED
        
        print("Checking CORS headers and uncommon charsets with the web server...")
        json_headers["value_disclosure"] = {}
        v_chk = False
        print()
        for valueh in value_headers:
            if valueh in headers:
                json_headers["value_disclosure"][valueh] = headers.get(valueh)
                if valueh == 'Access-Control-Allow-Credentials':
                    if json_headers["value_disclosure"][valueh] == "true":
                        print("Allow-Control-Access-Credentials is set to true!".format(colorize(valueh, 'warning')))
                
                if valueh == 'Content-type' and 'charset=' in (json_headers["value_disclosure"][valueh]):
                    if json_headers["value_disclosure"][valueh] not in {"text/html; charset=utf-8", "text/html; charset=iso-8859-1"}:
                        print("Unknown charset in Content-type!".format(colorize(valueh, 'warning')))
                        dojoUpdate(valueh, dp, json_headers["value_disclosure"][valueh])

                v_chk = True
        
        client_headers.update({'Origin': 'evil.com'})
        response = check_target(target, options)
        rUrl = response.geturl()
        parse_headers(response.getheaders())
        if 'Access-Control-Allow-Origin' in headers:
            if headers.get('Access-Control-Allow-Origin') == "evil.com":
                print("Allow-Control-Access-Control value reflected in response!".format(colorize(valueh, 'warning')))
                dojoUpdate(valueh, dp, "evil.com")
            elif headers.get('Access-Control-Allow-Origin') == "*":
                print("Allow-Control-Access-Control too weak (use of wildcard '*') in response!".format(colorize(valueh, 'warning'))) 
                dojoUpdate(valueh, dp, "*")
        client_headers.update({'Origin': 'null'})
        response = check_target(target, options)
        rUrl = response.geturl()
        parse_headers(response.getheaders())
        if 'Access-Control-Allow-Origin' in headers:
            if headers.get('Access-Control-Allow-Origin') == "null":
                print("Allow-Control-Access-Control null value in response!".format(colorize(valueh, 'warning')))
                dojoUpdate(valueh, dp, "null")
            elif headers.get('Access-Control-Allow-Origin') == "*":
                print("Allow-Control-Access-Control too weak (use of wildcard '*') in response!".format(colorize(valueh, 'warning')))
                dojoUpdate(valueh, dp, "*")
        if not v_chk:
            print("[*] No  value headers detected")
        ## ENDED


if __name__ == "__main__":

    parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])

    parser.add_option("-p", "--port", dest="port",
                      help="Set a custom port to connect to",
                      metavar="PORT")
    parser.add_option("-c", "--cookie", dest="cookie",
                      help="Set cookies for the request",
                      metavar="COOKIE_STRING")
    parser.add_option("-a", "--add-header", dest="custom_headers",
                      help="Add headers for the request e.g. 'Header: value'",
                      metavar="HEADER_STRING",
                      action="append")
    parser.add_option('-d', "--disable-ssl-check", dest="ssldisabled",
                      default=False,
                      help="Disable SSL/TLS certificate validation",
                      action="store_true")
    parser.add_option('-g', "--use-get-method", dest="useget",
                      default=False, help="Use GET method instead HEAD method",
                      action="store_true")
    parser.add_option("-j", "--json-output", dest="json_output",
                      default=False, help="Print the output in JSON format",
                      action="store_true")
    parser.add_option("-i", "--information", dest="information", default=False,
                      help="Display information headers",
                      action="store_true")
    parser.add_option("-x", "--caching", dest="cache_control", default=False,
                      help="Display caching headers",
                      action="store_true")
    parser.add_option("--proxy", dest="proxy",
                      help="Set a proxy (Ex: http://127.0.0.1:8080)",
                      metavar="PROXY_URL")
    parser.add_option("--hfile", dest="hfile",
                      help="Load a list of hosts from a flat file",
                      metavar="PATH_TO_FILE")
    parser.add_option("--dp", dest="dp",
                      help="Specify a DP ID to be updated.",
                      metavar="DP_ID")
    (options, args) = parser.parse_args()

    #if len(args) < 1 and options.hfile is None :
    #    parser.print_help()
    #    sys.exit(1)
    main(options, args)
