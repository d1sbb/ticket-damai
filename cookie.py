import asyncio
import json
import frida
from damai.performer import ApiFetchPerform

COOKIE = "cna=GTkNGg1FnBMCAd9bI9Vh4zCX; miid=4103237721956659179; tracknick=delete1110; lid=delete1110; thw=cn; sgcookie=E100jFdis%2FfgwtL84VQAyX9lk1U9Wd1OTGGolAPW1zbtS7h6bUU6gMRlZCPK3VMf7EHClo74iO%2B0Fj88O2v5q1cNwm483OqNerrM35fge9Q3J8U%3D; _cc_=W5iHLLyFfA%3D%3D; t=4a981f3ec04a4cfb2616b25f59395be2; _m_h5_tk=4008cd2491234172ee2be812b266db4c_1698508885070; _m_h5_tk_enc=d2e2eced5817a38adbdc45ff8857e66b; xlly_s=1; XSRF-TOKEN=fea50226-9209-4cc9-b9ac-c0333fbd448c; _samesite_flag_=true; cookie2=13522399341ebe776367c6c7315a2c48; _tb_token_=77e150785edf3; x5sec=7b22617365727665723b32223a223336366239653665373239323764343133323238643466613061316232636366434d724a694b6f47454a4c32674f6f464d4c53453664414751414d3d222c22733b32223a2230316234613737383065333766656333227d; tfstk=dSLD0HgWAnSjIeWDAxQjuqHb2Si8c-_1hdUOBNBZ4TW5WtLvDhxkOdXx1m_vqOvyEtSxGIIgSCX5WtLvDhxknKzODdLMVPAB1EhfWj_XGN_Zpv3dSIOf54tCFhAPcTIdbekKJ2djjqdIlvhjbz2fjkhTLplWPjjdK5MIVKIZdyXpgT4HNNCqP_0CdP5BosSD7QXaVureJGz1afLzflsVN_Xdz1ZAy; l=fBIwzJVrLu-5xIuMBO5Zourza77t3dRflsPzaNbMiIEGa6IfseEE_NCTgufw-dtjgT5vGZ-y9EDwTd3vr5438x1Hrt7APlUOrApp8e1pys4d.; isg=BExMHSOkRd2HHlY5Qh0hEO8WHap-hfAvQxb9XqYBzvfYMeY7gZCPvm_H0TkJeSiH"


def on_message(message, data):
    if message["type"] == "send":
        print("{0}".format(message["payload"]))
    else:
        print(message)


# hook代码
jscode = """
rpc.exports = {  
    myfunction: function (item_data){ 
        var ret = {};
        Java.perform(function () {
            const MtopRequest = Java.use("mtopsdk.mtop.domain.MtopRequest");
            let myMtopRequest = MtopRequest.$new();
            myMtopRequest.setApiName("mtop.trade.order.build");
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


def start_hook():
    # 开始hook
    process = frida.get_usb_device().attach("大麦")
    script = process.create_script(jscode)
    script.on("message", on_message)
    script.load()
    return script


script = start_hook()


async def make_cookie():
    item_id = '744129479098_1_5129200768594'
    ep = {
        "UMPCHANNEL_DM": "10001", "UMPCHANNEL_TPP": "50053", "atomSplit": '1',
        "channel": "damai_app", "coVersion": "2.0", "coupon": "true",
        "seatInfo": "", "subChannel": "", "umpChannel": "10001", "websiteLanguage": 'zh_CN_#Hans',
    }
    data = {
        "buyNow": "true", "buyParam": item_id,
        "exParams": json.dumps(ep, separators=(",", ":"))
    }
    item_data = json.dumps(data, separators=(",", ":"))
    instant = ApiFetchPerform()
    instant.hook_dm_data = script.exports.myfunction(item_data)
    instant.update_default_config(dict(COOKIE=COOKIE))
    response = await instant.build_order(item_data)
    print(response.get("ret"))
    #print(response.get("data", {}).get("url"))
    await instant.close()


asyncio.run(make_cookie())
