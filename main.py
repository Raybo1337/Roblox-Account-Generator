from typing import Any
from os import urandom
import base64
import random
import datetime
import logging
import colorlog
import json
import tls_client
import threading

formatter = colorlog.ColoredFormatter(
    '%(white)s[%(asctime)s] %(white)s%(log_color)s%(levelname)-8s %(white)s%(message)s',
    datefmt='%H:%M:%S',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)


class Utils:
    @staticmethod
    def generate_birth() -> str:
        b_year = random.randint(1980, 2000)
        b_month = random.randint(1, 12)
        b_day = Utils.get_rnd(b_month, b_year)
        return datetime.datetime(b_year, b_month, b_day,
                                 random.randint(0, 23), 0, 0, 0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'

    @staticmethod
    def get_rnd(b_month: int, b_year: int) -> int:
        days = {
            1: 31,
            2: 29 if b_year % 4 == 0 and (b_year % 100 != 0 or b_year % 400 == 0) else 28,
            3: 31,
            4: 30,
            5: 31,
            6: 30,
            7: 31,
            8: 31,
            9: 30,
            10: 31,
            11: 30,
            12: 31
        }
        return random.randint(1, days[b_month])


class Generator():
    def __init__(self):
        super().__init__()
        """
        Session info
        """
        self.session = tls_client.Session(client_identifier="chrome_107")
        self.session.proxies = "proxy_here"
        self.base_url = "https://www.roblox.com"
        self.base_auth = "https://auth.roblox.com/v2"
        self.base_ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" \
                       f"{random.randint(77, 115)}.0.{random.randint(100, 9999)}.{random.randint(10, 172)}" \
                       f" Safari/537.36 "

        """
        Client info
        """
        self.username = urandom(6).hex()
        self.password = urandom(6).hex().upper() + "!!B0wGen" # Change this if skid ;)

        """
        Arkose info
        """
        self.public_key = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"

    def obtain_headers(self, headers: dict = None) -> dict:
        headers = headers or {}
        headers.setdefault("Referer", self.base_url)
        headers.setdefault("User-Agent", self.base_ua)
        return headers

    def solve_captcha(self, blob: str) -> Any | None:
        return "Solve captcha with blob here..."

    def obtain_csrf(self) -> str | None:
        try:
            request = self.session.post(f"{self.base_auth}/signup", headers=self.obtain_headers())
            return request.headers['X-Csrf-Token']
        except:
            # logger.error("IP is banned and or ratelimited")
            return None

    def obtain_info(self, csrf_token: str, timestamp: str) -> dict | None:
        try:
            request = self.session.post(f"{self.base_auth}/signup",
                                        headers=self.obtain_headers({"x-csrf-token": csrf_token}),
                                        json={
                                            "username": self.username,
                                            "password": self.password,
                                            "birthday": timestamp,
                                            "gender": 2,
                                            "isTosAgreementBoxChecked": True,
                                            "agreementIds": [
                                                "54d8a8f0-d9c8-4cf3-bd26-0cbf8af0bba3",
                                                "848d8d8f-0e33-4176-bcd9-aa4e22ae7905"
                                            ]
                                        })
            data = json.loads(base64.b64decode(request.headers['Rblx-Challenge-Metadata']).decode('utf-8'))
            return {
                "captcha_id": data['unifiedCaptchaId'],
                "dataExchangeBlob": data['dataExchangeBlob'],
                "challenge_id": request.headers['Rblx-Challenge-Id']
            }
        except:
            # logger.error("IP is banned and or ratelimited")
            return None

    def register_user(self, csrf_token, timestamp, challenge, mdata) -> Any:
        body = self.obtain_headers({"x-csrf-token": csrf_token,
                                    "content-type": "application/json;charset=UTF-8",
                                    "host": "auth.roblox.com",
                                    "origin": self.base_url,
                                    "rblx-challenge-id": challenge,
                                    "rblx-challenge-metadata": mdata,
                                    "rblx-challenge-type": "captcha"})
        return self.session.post(f"{self.base_auth}/signup",
                                 headers=body,
                                 json={
                                     "username": self.username,
                                     "password": self.password,
                                     "birthday": timestamp,
                                     "gender": 2,
                                     "isTosAgreementBoxChecked": True,
                                     "agreementIds": [
                                         "54d8a8f0-d9c8-4cf3-bd26-0cbf8af0bba3",
                                         "848d8d8f-0e33-4176-bcd9-aa4e22ae7905"
                                     ]
                                 })

    def start(self) -> None:
        csrf = self.obtain_csrf()
        if csrf is None:
            self.start()
            return

        ts = Utils().generate_birth()
        info = self.obtain_info(csrf, ts)
        if info is None:
            self.start()
            return

        captcha_key = self.solve_captcha(info['dataExchangeBlob'])
        if captcha_key is None:
            self.start()
            return

        captcha_body = {
            "unifiedCaptchaId": info['captcha_id'],
            "captchaToken": captcha_key,
            "actionType": "Signup"
        }
        encoded_data = base64.b64encode(json.dumps(captcha_body).encode('ascii')).decode('ascii')

        reg_res = self.register_user(csrf, ts, info['challenge_id'], encoded_data)
        if "userId" in reg_res.text:
            logger.info(f"Successfully generated Roblox account: {self.username}{self.password}")
        else:
            logger.error(f"Failed to generate Roblox account: {self.username}{self.password}")
            self.start()


if __name__ == "__main__":
    for _ in range(30):
        threading.Thread(target=Generator().start).start()
