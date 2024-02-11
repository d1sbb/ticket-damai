import asyncio
import json
import sys
from loguru import logger
import frida
from damai.performer import ApiFetchPerform
from damai.utils import make_ticket_data, encode_gzip_base64, make_build_data
from damai.orderview import OrderView


# hook代码
jscode = """
rpc.exports = {  
    myfunction: function (aip_name,item_data){ 
        var ret = {};
        Java.perform(function () {
            const MtopRequest = Java.use("mtopsdk.mtop.domain.MtopRequest");
            let myMtopRequest = MtopRequest.$new();
            
            myMtopRequest.setApiName(aip_name);
            //item_id + count + ski_id  716435462268_1_5005943905715
            myMtopRequest.setData(item_data);
            myMtopRequest.setNeedEcode(true);
            myMtopRequest.setNeedSession(true);
            myMtopRequest.setVersion("4.0");
            //console.log(`${myMtopRequest}`)

            //引入Java中的类
            const MtopBusiness = Java.use("com.taobao.tao.remotebusiness.MtopBusiness");
            const MtopBuilder = Java.use("mtopsdk.mtop.intf.MtopBuilder");
            // let RemoteBusiness = Java.use("com.taobao.tao.remotebusiness.RemoteBusiness");
            const MethodEnum = Java.use("mtopsdk.mtop.domain.MethodEnum");
            const MtopListenerProxyFactory = Java.use("com.taobao.tao.remotebusiness.listener.MtopListenerProxyFactory");
            const System = Java.use('java.lang.System');
            const ApiID = Java.use("mtopsdk.mtop.common.ApiID");
            const MtopStatistics = Java.use("mtopsdk.mtop.util.MtopStatistics");
            const InnerProtocolParamBuilderImpl = Java.use('mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl');

            // create MtopBusiness
            let myMtopBusiness = MtopBusiness.build(myMtopRequest);
            myMtopBusiness.useWua();
            myMtopBusiness.reqMethod(MethodEnum.POST.value);
            myMtopBusiness.setCustomDomain("mtop.damai.cn");
            myMtopBusiness.setBizId(24);
            myMtopBusiness.setErrorNotifyAfterCache(true);
            myMtopBusiness.reqStartTime = System.currentTimeMillis();
            myMtopBusiness.isCancelled = false;
            myMtopBusiness.isCached = false;
            myMtopBusiness.clazz = null;
            myMtopBusiness.requestType = 0;
            myMtopBusiness.requestContext = null;
            myMtopBusiness.mtopCommitStatData(false);
            myMtopBusiness.sendStartTime = System.currentTimeMillis();

            let createListenerProxy = myMtopBusiness.$super.createListenerProxy(myMtopBusiness.$super.listener.value);
            let createMtopContext = myMtopBusiness.createMtopContext(createListenerProxy);
            let myMtopStatistics = MtopStatistics.$new(null, null); //创建一个空的统计类
            createMtopContext.stats.value = myMtopStatistics;
            myMtopBusiness.$super.mtopContext.value = createMtopContext;
            createMtopContext.apiId.value = ApiID.$new(null, createMtopContext);

            let myMtopContext = createMtopContext;
            myMtopContext.mtopRequest.value = myMtopRequest;
            let myInnerProtocolParamBuilderImpl = InnerProtocolParamBuilderImpl.$new();
            let res = myInnerProtocolParamBuilderImpl.buildParams(myMtopContext);

            // 增加了HashMap2Str函数，将HashMap类型转换为字符串
            function HashMap2Str(params_hm) {
              var HashMap=Java.use('java.util.HashMap');
              var args_map=Java.cast(params_hm,HashMap);
              return args_map.toString();
            };
            //console.log(`myInnerProtocolParamBuilderImpl.buildParams => ${HashMap2Str(res)}`)
            ret = HashMap2Str(res)
        });
        return ret;
    }
}  
"""


def on_message(message, data):
    if message["type"] == "send":
        print("{0}".format(message["payload"]))
    else:
        print(message)


def start_hook():
    # 开始hook
    process = frida.get_usb_device().attach("大麦")
    script = process.create_script(jscode)
    script.on("message", on_message)
    script.load()
    return script


script = start_hook()


class Gather(ApiFetchPerform):
    """根据POLL， COUNT进行并发
    建议不要改动，且不要多次调用。
    """
    POLL = 1
    COUNT = 1  # 2

    async def submit(self, item_id, sku_id, tickets):
        for _ in range(self.POLL):
            tasks = [self.leak_submit(item_id, sku_id, tickets) for _ in range(self.COUNT)]
            await asyncio.gather(*tasks)

    async def leak_submit(self, item_id, sku_id, tickets):
        set_Data = make_build_data(item_id, sku_id, tickets)
        aip_name = "mtop.trade.order.build"
        self.hook_dm_data = script.exports.myfunction(aip_name, set_Data)
        build_response = await self.build_order(set_Data)
        try:
            data = build_response.get("data")
            data = make_ticket_data(data)
            set_Data = encode_gzip_base64(data)
            aip_name = "mtop.trade.order.create"
            self.hook_dm_data = script.exports.myfunction(aip_name, set_Data)
            crate_response = await self.create_order(set_Data)
        except Exception as e:
            ret = ' '.join(build_response.get("ret", ''))
            logger.error(f'{type(e)} {e} {ret}')
            return ret
        else:
            build_ret = ' '.join(build_response.get("ret", ''))
            crate_ret = ' '.join(crate_response.get("ret", ''))
            logger.info(f'生成：{build_ret}, 创建：{crate_ret}')
            if "调用成功" in crate_ret:
                logger.info("抢票成功，前往app订单管理付款")
                notice(self.DEFAULT_CONFIG['ADDRESS'])
                sys.exit()
            if "您今天下单次数太多啦，休息一下明天再来吧~" in crate_ret:
                sys.exit()
            return build_ret + crate_ret


class SalableQuantity(Gather):
    """判断是否有库存，来减少一些不必要请求，避免频繁导致出现滑块。

    使用此类价格请使用int或list，否则会不兼容。

    支持按票价优先级抢，如
    PRICE=[3, 2, 1] ==> 前几次会抢3，没抢到会查依次查询PRICE对应的余票进行抢
    """

    DEFAULT_CONFIG = dict(
        **Gather.DEFAULT_CONFIG,
        CONCERT=1, PRICE=1
    )

    def __init__(self):
        super().__init__()
        self.order = OrderView()

    async def submit(self, item_id, sku_id, tickets):
        await super().submit(item_id, sku_id, tickets)
        await asyncio.sleep(2)

        data_id = self.get_data_id(item_id)
        # 查询可接受的库存
        while True:
            gen = self.pc_tags(item_id, data_id)
            for tags, sku_id in gen:
                if tags:
                    logger.debug(f'{tags}, {sku_id}')
                    continue

                future = await asyncio.gather(
                    self.leak_submit(item_id, sku_id, tickets),
                    self.leak_submit(item_id, sku_id, tickets)
                )
                ret = ' '.join(future)

                if any(i in ret for i in self.NECESSARY):
                    return

                if "RGV587_ERROR" in ret:
                    await asyncio.sleep(9.5)
                    break

                await asyncio.sleep(2)
                break

    def get_data_id(self, item_id):
        calendars = self.order.get_calendar_id_list(item_id)
        concert = self.DEFAULT_CONFIG["CONCERT"]
        concert = [concert] if isinstance(concert, int) else concert
        return [calendars[c - 1] for c in concert]

    def pc_tags(self, item_id, data_id):
        for id_ in data_id:
            data = self.order.make_perform_request(item_id, id_)
            perform = data.get("perform", {})
            sku_list = perform.get("skuList", [])
            price = self.DEFAULT_CONFIG["PRICE"]
            price = [price] if isinstance(price, int) else price
            for index in price:
                info = sku_list[index - 1]
                yield info.get("tags"), info.get('skuId')

    async def h5_tags(self, item_id):
        """暂时未用"""
        data = await self.get_detail(item_id)
        d = data.get("data", {})
        if not d:
            raise ValueError(data.get('ret'))
        result = json.loads(d["result"])
        performs = result["detailViewComponentMap"]["item"]["item"]["performBases"]
        sku = performs[0]['performs'][0]['skuList'][1]
        return sku.get("promotionTags", None)


def notice(*args, **kwargs):
    """通知功能
    对代码了解后不要通知也可以，但对代码不了解的请实现，有时候异步代码抢到了报错了
    别忘记付款。
    """
    logger.info(f"通知功能: {args}, {kwargs}")
