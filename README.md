# ScanBlocker

### Python Dependencies
* View requirements.txt
* to install automatically run `pip install -r requirements.txt`

### Linux Dependencies
IPTABLES 

   `sudo apt-get install iptables`
   
### Usage
`sudo python scanBlocker.py`

#### Usage Options
```-h, --help            show this help message and exit
  -H HOSTIP, --hostIP HOSTIP
                        Specify your host inet address. Will default to the
                        inet address of default interface.
  -i INTERFACE, --interface INTERFACE
                        Specify an interface to sniff for port scans on. Will
                        default to system default.
  -c, --clear           Use this flag to clear all blocked IPs before running. 
```
 `sudo python scanBlocker -i ens4 -H 10.138.0.27` 
 
 #### Clear out iptable rule chain 
 `sudo python scanBlocker -c`  
 or  
 ``` 
 sudo iptables -F
 sudo iptables -X 
 ```  
 #### View Blocked IP Addresses
 `Ctrl + C` while running  
 or  
 `sudo iptables -n -L` 
 
