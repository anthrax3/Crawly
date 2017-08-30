# Crawly v1.5
Web Application Screenshot Tool

#Description
>Crawly is a web application screenshot tool. 
>if you want to map list of valid IP's or Hostnames into screenshot images, Crawly is your choice.


#System Requirements
>Linux

>Python 2.x

>Please start Crawly with SUDO user

#Prerequisites
>sudo bash setup.sh

#Usage
>Start Crawly to scan range of IP's to ports 80,443,8080,8888, filter only 200 OK responses, and save png files.

```sh
$sudo python crawly.py -H 192.168.1.0/24 -port 80,443,8080,8888 -s 200 -e png
```

>Start Crawly to scan list of Hostnames from file to ports 80,443,8080,8888, perform Dirsearch on each of the results.

```sh
$sudo python crawly.py -F hosts.txt -port 80,443,8080,8888 -dirs
```

#Updates
>

#Future Work
>

