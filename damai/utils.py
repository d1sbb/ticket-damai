import hashlib
import json
import time
from importlib import import_module
from loguru import logger
# 滑块
import os
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
# 改yaml文件
import ruamel.yaml
# 加密
import base64
import gzip


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def get_sign(token, t, app_key, data):  # 未使用 H5页面获取sign的
    md5 = hashlib.md5()
    md5.update((token + '&' + str(t) + '&' + str(app_key) + '&' + data).encode('utf-8'))
    return md5.hexdigest()


def timestamp():
    return int(time.time() * 1000)


def load_object(path):
    if not isinstance(path, str):
        if callable(path):
            return path
        else:
            raise TypeError("Unexpected argument type, expected string "
                            "or object, got: %s" % type(path))

    try:
        dot = path.rindex('.')
    except ValueError:
        raise ValueError(f"Error loading object '{path}': not a full path")

    module, name = path[:dot], path[dot + 1:]
    mod = import_module(module)

    try:
        obj = getattr(mod, name)
    except AttributeError:
        raise NameError(f"Module '{module}' doesn't define any object named '{name}'")

    return obj


def make_ticket_data(order_build_data: dict):
    """构造订单form-data，购票人数，直接按账号实名人添加的顺序，不做详细处理
    order_build_data: 生成接口响应数据
    """
    params = {}
    data_field = ['confirmOrder_1', 'dmContactEmail', 'dmContactName', 'dmContactPhone',
                  'dmDeliveryAddress', 'dmDeliverySelectCard', 'dmEttributesHiddenBlock_DmAttributesBlock',
                  'dmPayType', 'dmViewer', 'item']
    data = order_build_data["data"]
    data_dict = {key: data[key] for field in data_field for key in data.keys() if
                 field == key or field == key.split('_')[0]}

    dmContactPhone = next(key for key in data_dict.keys() if key.split('_')[0] == "dmContactPhone")
    data_dict[dmContactPhone]["fields"]["cornerType"] = "bottom"

    dmPayType = next(key for key in data_dict.keys() if key.split('_')[0] == "dmPayType")
    data_dict[dmPayType]["fields"]["cornerType"] = "bottom"

    viewer = next(key for key in data_dict.keys() if key.split('_')[0] == "dmViewer")
    buyer_total_num = data_dict[viewer]["fields"].get('buyerTotalNum')
    if buyer_total_num:
        data_dict[viewer]["fields"]["selectedNum"] = buyer_total_num
        for index in range(int(buyer_total_num)):
            data_dict[viewer]["fields"]["viewerList"][index]["isUsed"] = "true"  # True
            data_dict[viewer]["fields"]["viewerList"][index]["used"] = True

            data_dict[viewer]["fields"]["viewerList"][index]["seatId"] = "0"
            data_dict[viewer]["fields"]["viewerList"][index]["idType"] = 1
            data_dict[viewer]["fields"]["viewerList"][index]["isPrivilegeAudience"] = False
            data_dict[viewer]["fields"]["viewerList"][index]["disabled"] = False
            data_dict[viewer]["fields"]["viewerList"][index].pop('maskedIdentityNo', None)

    params['data'] = data_dict

    endpoint = order_build_data["endpoint"]
    endpoint_dict = {field: endpoint[field] for field in ['mode', 'osVersion', 'protocolVersion', 'ultronage']}
    params['endpoint'] = endpoint_dict

    hierarchy = order_build_data["hierarchy"]
    hierarchy_dict = {field: hierarchy[field] for field in ['structure']}
    params['hierarchy'] = hierarchy_dict

    linkage = order_build_data["linkage"]
    linkage_dict = {field: linkage[field] for field in ['common', 'signature']}
    linkage_dict['common'].pop('queryParams', None)
    linkage_dict['common'].pop('structures', None)
    linkage_dict['common']['compress'] = True
    params['linkage'] = linkage_dict

    return dumps(params)


def make_build_data(item_id, sku_id, tickets):
    ep = {
        "UMPCHANNEL_DM": "10001", "UMPCHANNEL_TPP": "50053", "atomSplit": '1',
        "channel": "damai_app", "coVersion": "2.0", "coupon": "true",
        "seatInfo": "", "subChannel": "", "umpChannel": "10001", "websiteLanguage": 'zh_CN_#Hans',
    }  # zh_TW_#Hant zh_CN_#Hans
    set_Data = {
        "buyNow": "true", "buyParam": f'{item_id}_{tickets}_{sku_id}',
        "exParams": json.dumps(ep, separators=(",", ":"))
    }
    set_Data = json.dumps(set_Data, separators=(",", ":"))
    return set_Data


def get_x5sec_cookie(url):
    os.chdir(r"D:\soft\chrome-win64-test")
    subprocess.Popen('chrome.exe --remote-debugging-port=9527 --user-data-dir="D:\soft\python37\Lib\site-packages\selenium"')
    options = Options()
    options.add_experimental_option("debuggerAddress", "127.0.0.1:9527")
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    # delete_cookie(name,optionsString)：删cookie。name是要删除的cookie的名称，optionsString目前支持的选项包括“路径”，“域”
    while True:
        x5sec_cookie = driver.get_cookie("x5sec")
        if x5sec_cookie is not None:
            x5sec = x5sec_cookie['value']
            if driver.title == "淘宝":
                logger.info(f'更新：x5sec')  # {x5sec}
                driver.close()
                return x5sec
        else:
            if driver.title == "淘宝":
                if x5sec is not None:
                    logger.info(f'更新：x5sec')  # {x5sec}
                    driver.close()
                    return x5sec
                else:
                    return "000"


def save_yaml_cookie(cookie):
    yaml = ruamel.yaml.YAML()
    with open('C:/Users/QAQ/Desktop/ticket-damai/config.yaml', "r", encoding='utf-8') as f:
        code = yaml.load(f)
        code['COOKIE'] = cookie
        f.close()
    with open('C:/Users/QAQ/Desktop/ticket-damai/config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(code, f)  # 将Python中的字典或者列表转化为yaml格式的数据
        f.close()


def encode_gzip_base64(data):
    data = data.encode('utf-8')
    en64base = base64.b64encode(gzip.compress(data)).decode('utf-8')
    step = 76
    en64base_n = ""
    for i in range(0, len(en64base), step):
        en64base_n += en64base[i:i + step] + '\n'
    set_Data = {
        "feature": "{\"gzip\":\"true\"}", "params": en64base_n
    }
    set_Data = json.dumps(set_Data, separators=(",", ":"))
    return set_Data
