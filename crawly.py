# /usr/bin/python

'''
 Name: Crawly v1.5
 Author: Eran,Vaknin
 '''

import sys
import os
import requests
import argparse
import re
import itertools
import shutil
import glob
from netaddr import *
from termcolor import colored
import multiprocessing
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from string import Template
import subprocess, time



# SCAN FUNC
def scan(list1, ports, path, statuscode, tf, isfile, ext, savefile):
    uris = list()
    dcap = dict(DesiredCapabilities.PHANTOMJS)
    dcap["phantomjs.page.settings.userAgent"] = "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0"
    dcap["phantomjs.page.settings.javascriptEnabled"] = True
    uris.append('http://')
    uris.append('https://')
    if isfile:
        for hostscan in list1:
            for port in ports:
                for uri in uris:
                    try:
                        requests.packages.urllib3.disable_warnings()
                        req = requests.get(uri + hostscan + ":" + str(port) + str(path), timeout=6, verify=False)
                        if statuscode:
                            if str(req.status_code) in statuscode.split(","):
                                print colored("  [-] URL Detected: ", "green", attrs=[]) + colored(
                                    uri + hostscan + ":" + str(port) + str(path),
                                    "green", attrs=['bold']) + colored(" (" + str(req.status_code) + ")", "cyan",
                                                                       attrs=['bold'])
                                if not os.path.exists('ss/' + tf + '/' + port):
                                    os.makedirs('ss/' + tf + '/' + port)
                                br = webdriver.PhantomJS(
                                    service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'],
                                    desired_capabilities=dcap, service_log_path=os.path.devnull)
                                br.set_window_size(819, 460)
                                br.get(uri + hostscan + ":" + str(port) + str(path))
                                br.save_screenshot(
                                    'ss/' + tf + '/' + str(port) + "/" + str(req.status_code) + "-" + str(
                                        port) + "-" + hostscan + "." + str(ext))
                                br.quit()
                                save_result(str(os.getpid()) + ".txt",
                                            str(uri) + str(hostscan) + ":" + str(port) + str(path), "scan", savefile,
                                            str(port))
                        else:
                            if req.status_code:
                                print colored("  [-] URL Detected: ", "green", attrs=[]) + colored(
                                    uri + hostscan + ":" + str(port) + str(path),
                                    "green", attrs=['bold']) + colored(" (" + str(req.status_code) + ")", "cyan",
                                                                       attrs=['bold'])
                                if not os.path.exists('ss/' + tf + '/' + port):
                                    os.makedirs('ss/' + tf + '/' + port)
                                br = webdriver.PhantomJS(
                                    service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'],
                                    desired_capabilities=dcap, service_log_path=os.path.devnull)
                                br.set_window_size(819, 460)
                                br.get(uri + hostscan + ":" + str(port) + str(path))
                                br.save_screenshot(
                                    'ss/' + tf + '/' + str(port) + "/" + str(req.status_code) + "-" + str(
                                        port) + "-" + hostscan + "." + str(ext))
                                br.quit()
                                save_result(str(os.getpid()) + ".txt",
                                            str(uri) + str(hostscan) + ":" + str(port) + str(path), "scan", savefile)
                    except KeyboardInterrupt:
                        sys.exit(0)
                    except:
                        pass
    elif not isfile:
        for hostscan in list1:
            hostscan = hostscan.rstrip('\r\n')
            for port in ports:
                for uri in uris:
                    try:
                        requests.packages.urllib3.disable_warnings()
                        req = requests.get(uri + hostscan + ":" + str(port) + str(path), timeout=6, verify=False)
                        if statuscode:
                            if str(req.status_code) in statuscode.split(","):
                                print colored("  [-] URL Detected: ", "green", attrs=[]) + colored(
                                    uri + hostscan + ":" + str(port) + str(path), "green", attrs=['bold']) + colored(
                                    " (" + str(req.status_code) + ")", "cyan", attrs=['bold'])
                                if not os.path.exists('ss/' + tf + '/' + port):
                                    os.makedirs('ss/' + tf + '/' + port)
                                br = webdriver.PhantomJS(
                                    service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'],
                                    desired_capabilities=dcap, service_log_path=os.path.devnull)
                                br.get(uri + hostscan + ":" + str(port) + str(path))
                                br.save_screenshot(
                                    'ss/' + tf + '/' + str(port) + "/" + str(req.status_code) + "-" + str(
                                        port) + "-" + hostscan + "." + str(ext))
                                br.quit()
                                save_result(str(os.getpid()) + ".txt",
                                            str(uri) + str(hostscan) + ":" + str(port) + str(path), "scan", savefile)
                        else:
                            if req.status_code:
                                print colored("  [-] URL Detected: ", "green", attrs=[]) + colored(
                                    uri + hostscan + ":" + str(port) + str(path), "green", attrs=['bold']) + colored(
                                    " (" + str(req.status_code) + ")", "cyan", attrs=['bold'])
                                if not os.path.exists('ss/' + tf + '/' + port):
                                    os.makedirs('ss/' + tf + '/' + port)
                                br = webdriver.PhantomJS(
                                    service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'],
                                    desired_capabilities=dcap, service_log_path=os.path.devnull)
                                br.get(uri + hostscan + ":" + str(port) + str(path))
                                br.save_screenshot(
                                    'ss/' + tf + '/' + str(port) + "/" + str(req.status_code) + "-" + str(
                                        port) + "-" + hostscan + "." + str(ext))
                                br.quit()
                                save_result(str(os.getpid()) + ".txt",
                                            str(uri) + str(hostscan) + ":" + str(port) + str(path), "scan", savefile)
                    except KeyboardInterrupt:
                        sys.exit(0)
                    except:
                        pass


# SAVE RESULTS FUNC
def save_result(tfile, result, stype, savefile):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    f = open(dir_path + '/temp/' + savefile + '/scan_' + stype + tfile, 'a')
    f.write(result + "\n")
    f.close()


# MERGE RESULTS FUNC
def merge_results(stype, dirpath):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    files = glob.glob(dir_path + "/temp/" + dirpath + "/scan_" + str(stype) + "*.txt")
    with open(dir_path + '/temp/' + dirpath + '/result' + str(stype) + '.txt', 'a') as result:
        for file_ in files:
            for line in open(file_, 'r'):
                result.write(line + "\r\n")


# EXPORT REPORT.HTML FUNC
def export(t7,dirfile):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    imgpath = list()

    for path, subdirs, files in os.walk(t7):
        for name in files:
            html_t = '<div><a href="#"><img class="img-fluid img-thumbnail" src="'+os.path.join(name.split('-')[1], name)+'" alt=""></a></div>'
            imgpath.append(html_t)

    try:
        subprocess.Popen("cp -r "+dir_path+"/template/* "+t7+"/", shell=True, stdout=subprocess.PIPE).stdout.read()
    except:
        pass

    template_file = open(dir_path + '/template/index.html', 'r')
    src = Template(template_file.read())
    sub_dict = {'json_image_path': '\n'.join(imgpath)}
    result = src.substitute(sub_dict)
    template_file.close()
    fileout = open(t7+'/index.html', 'w')
    fileout.write(result)
    fileout.close()
    cleanup(dirfile)

    print colored(" [-] Report at http://127.0.0.1:8081 ", "yellow", attrs=[])

    try:
        proc = subprocess.Popen("cd "+t7+"/ && "+"python -m SimpleHTTPServer 8081", shell=True)
        raw_input(" [-] Press ctrl+c any key to stop server...")
    finally:
        time.sleep(2)
        proc.kill()
        proc.kill()
        print " [-] Exiting Crawly..."


# CHECK ROOT FUNC
def check_root():
    if not os.geteuid() == 0:
        print colored("[!] Crawly Must Run As Root", "red", attrs=['bold'])
        sys.exit(0)


# CLEANUP FUNC
def cleanup(dirpath):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if os.path.exists(dir_path + '/temp/' + dirpath):
        shutil.rmtree(dir_path + '/temp/' + dirpath)


# INITIATE CRAWLYBUST FUNC
def initiate_dirs(tf, extension, dir_path):
    dirhosts = set()
    for root, subFolders, files in os.walk(dir_path + '/ss/' + tf):
        for f in files:
            temp = f.split("-")
            if temp[1] == "443" or temp[1] == "8443":
                dirhosts.add("https://" + temp[2].split("." + extension)[0] + ":" + temp[1])
            else:
                dirhosts.add("http://" + temp[2].split("." + extension)[0] + ":" + temp[1])
    for i in dirhosts:
        try:
            sub = subprocess.Popen(
                "python3.5 " + dir_path + "/dirsearch/dirsearch.py -u " + i + " -e php,aspx,asp,jsp,xml", shell=True,
                stdout=sys.stdout, stdin=subprocess.PIPE)
            sub.communicate()
        except:
            time.sleep(5)
            sub.kill()


# SPLIT BIG LIST BY SIZE FUNC
def split(iterable, size):
    it = iter(iterable)
    item = list(itertools.islice(it, size))
    while item:
        yield item
        item = list(itertools.islice(it, size))


# DEFINE IP ADDRS FUNC
def check_ip(ip):
    global bigip
    temp = IPNetwork(ip)
    for i in temp:
        bigip.append(str(i))

def update_dirsearch():
    FNULL = open(os.devnull, 'w')
    subprocess.Popen("cd dirsearch && git pull", shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

# MAIN FUNC
def main():
    print colored("""
             /$$$$$$                                    /$$          
            /$$__  $$                                  | $$          
            | $$  \__/  /$$$$$$  /$$$$$$  /$$  /$$  /$$| $$ /$$   /$$
            | $$       /$$__  $$|____  $$| $$ | $$ | $$| $$| $$  | $$
            | $$      | $$  \__/ /$$$$$$$| $$ | $$ | $$| $$| $$  | $$
            | $$    $$| $$      /$$__  $$| $$ | $$ | $$| $$| $$  | $$
            |  $$$$$$/| $$     |  $$$$$$$|  $$$$$/$$$$/| $$|  $$$$$$$
             \______/ |__/      \_______/ \_____/\___/ |__/ \____  $$
                                                            /$$  | $$
              Web Application ScreenShot Script             |  $$$$$$/
              Author:Eran.Vaknin(B4RD4K)                    \______/ 
              """, "green", attrs=['bold'])

    # CHECK IF CRAWLY RUN AS ROOT
    check_root()

    # CHECK IF DIRSEARCH HAS UPDATES
    update_dirsearch()

    # VARIABLE DEFINING
    global bigip
    jobs = []
    bigip = list()
    times = time.strftime("%d.%H.%M.%S")
    dir_path = os.path.dirname(os.path.realpath(__file__))
    ipregex = re.compile(r'(https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?')
    urlregex = re.compile(r'(https?:\/\/)?([\da-zA-Z\.-]+)\.([a-zA-Z\.]{2,6})?')
    drs = None

    # ARGPARSER ARGUMENTS
    parser = argparse.ArgumentParser(
        description=colored("Crawly v1.5 ", "blue", attrs=['bold']) + "|" + colored(
            ' Simple Web Application Screnshot Script', 'blue', attrs=['bold']),
        epilog='''Usage:\r\n  sudo python crawly.py -H ''' + colored("192.168.1.1/24", "blue",
                                                                     attrs=['bold']) + ''' -port ''' + colored(
            "80,443,8080", "blue", attrs=['bold']) + ''' -c ''' + colored("files/folders/all", "blue",
                                                                          attrs=['bold']) + ''' -t ''' + colored("20",
                                                                                                                 'blue',
                                                                                                                 attrs=['bold']) + ''' -e ''' + colored(
            "jpg", 'blue', attrs=['bold']) + ''' -s ''' + colored("200,401", 'blue', attrs=['bold']) +
               '''\r\n  sudo python crawly.py -F ''' + colored("address.txt", "blue",
                                                               attrs=['bold']) + ''' -port ''' + colored("80,443,8080",
                                                                                                         "blue", attrs=[
                'bold']) + ''' -c ''' + colored("files/folders/all", "blue", attrs=['bold']) + ''' -t ''' + colored(
            "20", 'blue', attrs=['bold']) + ''' -e ''' + colored("jpg", 'blue', attrs=['bold']) + ''' -s ''' + colored(
            "200,401", 'blue', attrs=['bold']),
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-H', '--host', help='HOSTNAME', required=False)
    parser.add_argument('-port', help='PORT NUMBER e.g: 80,8080,443', required=True)
    parser.add_argument('-P', '--path', help='PATH e.g:/robots.txt', required=False)
    parser.add_argument('-F', '--file', help='FILE e.g:/root/Desktop/host_file.txt', required=False)
    parser.add_argument('-T', help='CRAWLY THREADS, default:5', required=False)
    parser.add_argument('-d', '--dirs', help='Start DirSearch Tool', required=False)
    parser.add_argument('-s', '--sc', help='STATUS CODE e.g: 200,300', required=False)
    parser.add_argument('-e', '--ext', help='FILE EXTENSION e.g: jpg,png, default:png', required=False)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()

    # TEMPORARY INPUT VALIDATION :)
    if args.path:
        path = args.path
    else:
        path = "/"
    if args.sc:
        statuscode = args.sc
    else:
        statuscode = None
    if not args.T:
        threads = 5
    else:
        threads = int(args.T)
    if args.ext:
        extension = args.ext
    else:
        extension = "png"
    if args.dirs is not None:
        drs = 1


    if not os.path.exists(dir_path + '/temp'):
        os.makedirs(dir_path + '/temp')

    temp_save_path = dir_path + '/temp/' + str(times)
    os.makedirs(temp_save_path)

    # FILE SCAN DETECTED
    if args.file and os.path.exists(args.file) and not args.host:

        print colored("[+] Scanning File: ", "green", attrs=['bold'])
        print colored(" [-] Scan File: ", "yellow", attrs=[]) + colored(str(args.file), "blue", attrs=['bold'])
        print colored(" [-] Ports: ", "yellow", attrs=[]) + colored(str(args.port.split(",")), "blue", attrs=['bold'])
        print colored(" [-] StatusCode Filtering: ", "yellow", attrs=[]) + colored(str(statuscode), "blue",
                                                                                   attrs=['bold'])
        print colored(" [-] URL Path: ", "yellow", attrs=[]) + colored(str(path), "blue", attrs=['bold'])
        print colored(" [-] ScreenShot Extension: ", "yellow", attrs=[]) + colored(str(extension), "blue",
                                                                                   attrs=['bold'])
        print colored(" [-] Scan Threads: ", "yellow", attrs=[]) + colored(str(threads), "blue", attrs=['bold'])

        if not os.path.exists(dir_path + '/ss/' + args.file):
            tf = "scan_" + str(times)
            os.makedirs('ss/' + tf)
        else:
            shutil.rmtree(dir_path + '/ss/' + args.file)
            os.makedirs(dir_path + '/ss/' + args.file)
            tf = "scan_" + str(times)

        with open(args.file, 'r') as lines:
            for line in lines:
                if line.strip() is not '':
                    if re.match(ipregex, line):
                        temp = re.match(ipregex, line).group()
                        if "http://" in temp:
                            line1 = temp.replace('http://', '', 1)
                        elif "https://" in temp:
                            line1 = temp.replace('https://', '', 1)
                        else:
                            line1 = temp
                        check_ip(line1.rstrip())
                    elif re.match(urlregex, line):
                        temp = re.match(urlregex, line).group()
                        if "http://" in temp:
                            line1 = temp.replace('http://', '', 1)
                        elif "https://" in temp:
                            line1 = temp.replace('https://', '', 1)
                        else:
                            line1 = temp
                        bigip.append(line1.rstrip())

        num_lines = sum(1 for line in bigip)

        if int(threads) >= int(num_lines):
            print colored(" [-] Crawly Short Scan Detected", "yellow", attrs=[])
            threads = 1

        print ""
        print colored("[+] Crawly Scan Results: ", "green", attrs=['bold'])
        print colored(" [+] Results Folder: ", "yellow", attrs=[]) + colored(dir_path + "/ss/" + str(tf), "blue",
                                                                             attrs=['bold'])

        delta = num_lines / int(threads)
        newbigip = set(bigip)
        listoflists = list(split(list(newbigip), int(delta)))

        for list1 in listoflists:
            p = multiprocessing.Process(target=scan, args=(list1, args.port.split(","), path, statuscode, tf, True, extension, str(times)))
            jobs.append(p)
            p.start()
        [p.join() for p in jobs]

        # DirSearch Detected
        if drs is not None:
            initiate_dirs(tf, extension, dir_path)
            export(dir_path + "/ss/" + str(tf), str(times))
        else:
            print ""
            print colored("[+] Finishing Scan...", "green", attrs=['bold'])
            merge_results("scan", str(times))
            export(dir_path + "/ss/" + str(tf), str(times))

    # IP SCAN DETECTED
    elif args.host and re.match(ipregex, args.host) and not args.file:
        temp = re.match(ipregex, args.host).group()

        if "http://" in temp:
            ip = temp.replace('http://', '', 1)
        elif "https://" in temp:
            ip = temp.replace('https://', '', 1)
        else:
            ip = temp

        print colored("[+] Crawly Scan Config: ", "green", attrs=['bold'])
        print colored(" [-] Scanning IP: ", "yellow", attrs=[]) + colored(str(ip), "blue", attrs=['bold'])
        print colored(" [-] Ports: ", "yellow", attrs=[]) + colored(str(args.port.split(",")), "blue", attrs=['bold'])
        print colored(" [-] StatusCode Filtering: ", "yellow", attrs=[]) + colored(str(statuscode), "blue",
                                                                                   attrs=['bold'])
        print colored(" [-] URL Path: ", "yellow", attrs=[]) + colored(str(path), "blue", attrs=['bold'])
        print colored(" [-] ScreenShots Extension: ", "yellow", attrs=[]) + colored(str(extension), "blue",
                                                                                    attrs=['bold'])
        print colored(" [-] Scan Threads: ", "yellow", attrs=[]) + colored(str(threads), "blue", attrs=['bold'])

        if "/" in ip:
            ipname = ip.split("/")[0]
        elif "/" not in ip:
            ipname = ip.split(".")[0] + "." + ip.split(".")[1] + "." + ip.split(".")[2] + "." + ip.split(".")[3]
        if not os.path.exists(dir_path + '/ss/' + ipname):
            os.makedirs(dir_path + '/ss/' + ipname)
            tf = ipname
        else:
            shutil.rmtree(dir_path + '/ss/' + ipname)
            os.makedirs(dir_path + '/ss/' + ipname)
            tf = ipname

        check_ip(ip)
        num_ip = sum(1 for line in bigip)

        if int(threads) >= int(num_ip):
            print colored(" [-] Crawly Short Scan Detected", "yellow", attrs=[])
            threads = 1
        print ""
        print colored("[+] Crawly Scan Results: ", "green", attrs=['bold'])
        print colored(" [+] Results Folder: ", "yellow", attrs=[]) + colored(dir_path + "/ss/" + str(tf), "blue",
                                                                             attrs=['bold'])
        delta = int(num_ip) / int(threads)
        newbigip = set(bigip)
        listoflists = list(split(list(newbigip), int(delta)))
        for list1 in listoflists:
            p = multiprocessing.Process(target=scan, args=(
            list1, args.port.split(","), path, statuscode, tf, False, extension, str(times)))
            jobs.append(p)
            p.start()
        [p.join() for p in jobs]

        # DirSearch Detected
        if drs is not None:
            initiate_dirs(tf, extension, dir_path)
            export(dir_path + "/ss/" + str(tf), str(times))
        else:
            print ""
            print colored("[+] Finishing Scan...", "green", attrs=['bold'])
            merge_results("scan", str(times))
            export(dir_path + "/ss/" + str(tf), str(times))

    # HOST SCAN DETECTED
    elif args.host and re.match(urlregex, args.host) and not args.file:
        temp = re.match(urlregex, args.host).group()
        if "http://" in temp:
            host = temp.replace('http://', '', 1)
        elif "https://" in temp:
            host = temp.replace('https://', '', 1)
        else:
            host = temp
        if not os.path.exists('ss/' + host):
            os.makedirs('ss/' + host)
            tf = host
        else:
            shutil.rmtree('ss/' + host)
            os.makedirs('ss/' + host)
            tf = host

        print colored("[+] Crawly Scan Config: ", "green", attrs=['bold'])
        print colored(" [-] Scanning Host: ", "yellow", attrs=[]) + colored(str(temp), "blue", attrs=['bold'])
        print colored(" [-] Ports: ", "yellow", attrs=[]) + colored(str(args.port.split(",")), "blue", attrs=['bold'])
        print colored(" [-] StatusCode Filtering: ", "yellow", attrs=[]) + colored(str(statuscode), "blue",
                                                                                   attrs=['bold'])
        print colored(" [-] URL Path: ", "yellow", attrs=[]) + colored(str(path), "blue", attrs=['bold'])
        print colored(" [-] ScreenShots Extension: ", "yellow", attrs=[]) + colored(str(extension), "blue",
                                                                                    attrs=['bold'])
        print colored(" [-] Scan Threads: ", "yellow", attrs=[]) + colored(str(threads), "blue", attrs=['bold'])
        bigip.append(host.rstrip())
        num_ip = sum(1 for line in bigip)
        if int(threads) >= int(num_ip):
            print colored(" [-] Crawly Short Scan Detected", "yellow", attrs=[])
        print ""
        print colored("[+] Crawly Scan Results: ", "green", attrs=['bold'])
        print colored(" [+] Results Folder: ", "yellow", attrs=[]) + colored(dir_path + "/ss/" + str(host), "blue",
                                                                             attrs=['bold'])

        scan(bigip, args.port.split(","), path, statuscode, tf, False, extension, str(times))

        # DirSearch Detected
        if drs is not None:
            initiate_dirs(tf, extension, dir_path)
            export(dir_path + "/ss/" + str(tf), str(times))
        else:
            print ""
            print colored("[+] Finishing Scan...", "green", attrs=['bold'])
            merge_results("scan", str(times))
            export(dir_path + "/ss/" + str(tf), str(times))
    else:
        print colored("[!] Check Arguments And Try Again!", "red", attrs=['bold'])
        sys.exit(0)


if __name__ == '__main__':
    main()
