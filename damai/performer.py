import asyncio
import random
import re
from collections import Counter
from urllib import parse
import aiohttp
from aiohttp import TCPConnector
from loguru import logger


from damai.utils import make_ticket_data, get_x5sec_cookie, save_yaml_cookie


class Perform:

    DEFAULT_CONFIG = dict()

    def update_default_config(self, configs: dict):
        for key in self.DEFAULT_CONFIG.keys():
            if key in configs:
                self.DEFAULT_CONFIG[key] = configs[key]

    def submit(self, item_id, sku_id, tickets):
        raise NotImplementedError()


class ApiFetchPerform(Perform):
    """接口请求购票"""

    DEFAULT_CONFIG = dict(
        **Perform.DEFAULT_CONFIG,
        USER_AGENT="MTOPSDK%2F3.1.1.7+%28Android%3B9%3BOnePlus%3BKB2001%29",
        APP_KEY=23781390, RETRY=100, FAST=2, COOKIE=None, ADDRESS='地地道道'
    )
    NECESSARY = {"商品信息已过期", "Session", "令牌过期", "FAIL_SYS_USER_VALIDATE",
                 "未支付订单", "异常", "特权", "次数太多"}
    SECONDARY = {"库存", "挤爆"}

    def __init__(self):
        super().__init__()
        self.connector = TCPConnector(ssl=False)
        self.session = aiohttp.ClientSession(connector=self.connector)
        self.hook_dm_data = ""
        self.Content_Length = "0"

    @property
    def headers(self):
        x_sgext = parse.quote_plus(self.hook_dm_data.split(", ")[1].split("sgext=")[1])
        x_sign = parse.quote_plus(self.hook_dm_data.split(", ")[5].split("sign=")[1])
        x_mini_wua = parse.quote_plus(self.hook_dm_data.split(", ")[11].split("wua=")[1])
        x_t = self.hook_dm_data.split(", ")[21].split("=")[1]
        # 上面为必须值
        x_utdid = parse.quote_plus(self.hook_dm_data.split(", ")[16].split("=")[1])
        x_ttid = parse.quote_plus(self.hook_dm_data.split(", ")[20].split("=")[1])
        x_sid = self.hook_dm_data.split(", ")[7].split("=")[1]
        x_uid = self.hook_dm_data.split(", ")[8].split("=")[1]
        x_umt = self.hook_dm_data.split(", ")[14].split("=")[1]
        number = 174
        padded_number = format(int(number), "04")
        f71332q = "117713"
        x_c_traceid = str(x_utdid) + (str(x_t+"235")) + (str(padded_number)) + (str(f71332q))
        return {
            "Cookie": self.DEFAULT_CONFIG["COOKIE"],
            "x-sgext": x_sgext,
            "x-bx-version": "6.6.230507",
            "f-refer": "mtop",
            "x-ttid": x_ttid,
            "x-app-ver": "8.7.1",
            "x-sign": x_sign,
            "x-sid": x_sid,
            "x-c-traceid": x_c_traceid,
            "x-uid": x_uid,
            "x-nettype": "WIFI",
            "x-pv": "6.3",
            "x-nq": "WIFI",
            "x-features": "27",
            "x-app-conf-v": "0",
            "x-umt": x_umt,
            "x-mini-wua": x_mini_wua,
            "x-utdid": x_utdid,
            "x-appkey": str(self.DEFAULT_CONFIG["APP_KEY"]),
            "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Content-Length": self.Content_Length,
            "x-t": x_t,
            "user-agent": self.DEFAULT_CONFIG["USER_AGENT"],
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Host": "mtop.damai.cn",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive"
        }

    def update_default_config(self, configs):
        super().update_default_config(configs)
        if not self.DEFAULT_CONFIG["COOKIE"]:
            raise ValueError(f"{self}需要配置COOKIE")

    async def submit(self, item_id, sku_id, tickets):
        """购票流程

        RETRY: 退出购票的条件，当响应某个值到达一定次数将结束购票。如果能确保不出现验证码
        可以把值配置的更高，持续时间长捡票。
        """
        fast = self.DEFAULT_CONFIG["FAST"] - 1
        counter = Counter()
        c_ret = ''

        while all(counter.get(i, 0) < self.DEFAULT_CONFIG["RETRY"] for i in self.SECONDARY):
            response = await self.build_order(f'{item_id}_{tickets}_{sku_id}')
            b_ret = ' '.join(response["ret"])
            logger.info(f'生成订单：{b_ret}')

            if "调用成功" in b_ret:
                data = response.get("data", {})
                if not data.get("data"):
                    break
                data = make_ticket_data(data)
                response = await self.create_order(data)
                c_ret = ' '.join(response["ret"])
                logger.info(f"创建订单：{c_ret}")
                counter.update([self.detection(c_ret)])
                if "调用成功" in c_ret:
                    logger.info("抢票成功，前往app订单管理付款")
                    break
            counter.update([self.detection(b_ret)])

            if any(i in b_ret or i in c_ret for i in self.NECESSARY):
                break

            if fast:
                fast -= 1
                continue

            await asyncio.sleep(random.uniform(1, 1.5))

    def detection(self, sting):
        for field in {*self.SECONDARY, *self.NECESSARY}:
            if field in sting:
                return field
            return sting

    async def build_order(self, data_buy):
        wua = parse.quote_plus(self.hook_dm_data.split(", ")[0].split("wua=")[1])
        data1 = "wua=" + wua + "&data=" + parse.quote_plus(data_buy)
        self.Content_Length = str(len(data1))
        url = f'https://mtop.damai.cn/gw/mtop.trade.order.build/4.0/'
        req = await self.session_post_CAPTCHA(url, data1)
        return req

    async def create_order(self, data):
        wua = parse.quote_plus(self.hook_dm_data.split(", ")[0].split("wua=")[1])
        data1 = "wua=" + wua + "&data=" + parse.quote_plus(data)
        self.Content_Length = str(len(data1))
        url = 'https://mtop.damai.cn/gw/mtop.trade.order.create/4.0/'
        req = await self.session_post_CAPTCHA(url, data1)
        return req

    async def session_post_CAPTCHA(self, url, data):
        async with self.session.post(url, data=data,
                                     headers=self.headers) as response:
            req = await response.json()
            if req.get("data") == {}:
                if req.get("ret") == ['FAIL_SYS_USER_VALIDATE::哎哟喂,被挤爆啦,请稍后重试!']:
                    New_x5sec = get_x5sec_cookie(response.headers['Location'])
                    x5sec_reg = r'x5sec=(.*?); '
                    slotList = re.findall(x5sec_reg, self.DEFAULT_CONFIG["COOKIE"])
                    self.DEFAULT_CONFIG["COOKIE"] = self.DEFAULT_CONFIG["COOKIE"].replace(slotList[0], New_x5sec)
                    save_yaml_cookie(self.DEFAULT_CONFIG["COOKIE"])
                    # 更新cookie后再次post
                    async with self.session.post(url, data=data,
                                                 headers=self.headers) as response1:
                        return await response1.json()
            return req

    async def close(self):
        await self.session.close()
