# Ultra-Fast Traceroute (UFT)
_Creators:_   
_Yuvraj Singh Malhi (BITS Pilani Electronics)_   
_Shivam Goyal       (BITS Pilani Computers)_   

## Description
Traceroute is a very famous networking tools to determine the path from a machine to another machine. 

Traditionally, a traceroute would use the ICMP protocol which the routers understand. In every second, 3 ICMP packets are sent to the destination with increasing _TTL_ (time to live) starting from 1, then 2, then 3.. and so on.

_For TTL = 1_ : The most immediate router from the host to the destination is found.
_For TTL = 2_ : The second most immediate router from host to destination is found. 
_For TTL = 3_ : The third most immediate router from host to destination is found. 
.. and so on.

This goes on till the destination is reached. Hence, all the routers in the path have been identified.

In linux,
the command to use traceroute for _google.com_  would be:   
``` traceroute google.com ```   


![image](https://user-images.githubusercontent.com/76866159/107151082-c5ccce80-6986-11eb-8345-66755612f33b.png)

**Default traceroute vs Ultra-Fast Traceroute (UFT)**:  

CRITERIA | DEFAULT TRACEROUTE | UFT
-------|-------| ------------
SPEED | Takes ~ 20 seconds per URL | Takes < 2 seconds
MULTIPLE COMMANDS | To be given one-by-one | Can take multiple in one go from a file
MULTIPROCESS | Total time = (no. of URLs) X 20 seconds | Total time = 2 seconds irrespective of no. of URLs
CORRELATION | No functionality here | Finds the longest common path between the URLs specified 

## Usage 
Run the following commands if using for the fist time:  
``` git clone https://github.com/yuvrajmalhi/Ultra-Fast-Traceroute.git ```  
``` cd Ultra-Fast-Traceroute/ ```  
``` sudo make ```  

Now, in _domain.txt_ enter list of all the domains that you want to run traceroute on.
By default, the following domains will be used: google, facebook, instagram, and twitter.

Now, open another terminal (or simple split the current terminal into two) and use the cd command to navigate to the same folder 'Ultra-Fast-Traceroute/'.

Finally, 
On one terminal run: ```sudo ./fastertraceroute ```   
On the other terminal run: ```sudo ./findlongestcommonpath```   

Give ~2 seconds.


Voila! Expand the second terminal to see the results of individual traceroute and also the longest common path.

![Peek 2021-02-07 13-38](https://user-images.githubusercontent.com/76866159/107151656-b733e680-6989-11eb-9e85-fe6f153fd57e.gif)

Do share if you liked our work. Thanks!

:smile:
