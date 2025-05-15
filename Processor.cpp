#include "Processor.h"
#include "LoginServer.h"
#include "globe.h"
#include "LogComm.h"
#include "DataProxyProto.h"
#include "ServiceDefine.h"
#include "util/tc_hash_fun.h"
#include "LogDefine.h"
#include "uuid.h"
#include "CommonCode.pb.h"
#include <regex>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <regex.h>
#include <assert.h>
#include "pcre.h"
#include "UserInfo.pb.h"
#include "jwt-cpp/jwt.h"
#include "iostream"
#include "cppcodec/base64_url_unpadded.hpp"

#define MIN_USERNAME_LEN 1           //用户名长度
#define MIN_PASSWD_LEN 4             //密码长度
#define MAX_UID_NUMBER_PER_ACCOUNT 1 //每个账号对应一个uid
#define TOKEN_EXPTIME 6 * 3600

using namespace std;
using namespace dataproxy;
using namespace dbagent;
using namespace userinfo;

// extern tars::Int32 getAreaID(const string &addr);
// extern tars::Int32 getAreaID(const map<std::string, std::string> &extraInfo, AreaIDReq &req, AreadIDResp &rsp);

//拆分字符串
static vector<std::string> split(const string &str, const string &pattern)
{
    return TC_Common::sepstr<string>(str, pattern);
}

//格式化时间
static std::string CurTimeFormat()
{
    std::string sFormat("%Y%m%d%H%M");
    time_t t = TNOW;
    auto ptr = localtime(&t);
    if (!ptr)
        return string("");

    char buffer[255] = "\0";
    strftime(buffer, sizeof(buffer), sFormat.c_str(), ptr);
    return string(buffer);
}

/**
 * 检查手机号码有效性
 * @param  str [description]
 * @return     [description]
 */
static bool checkPhoneNumber(std::string str)
{
    if (str.empty())
        return false;

    int erroff;
    const char *error;
    // const char *pattern = "^1([3-9])\\d{9}$";
    const char *pattern = "^[0-9]*$";//纯数字
    pcre *ptr = pcre_compile(pattern, 0, &error, &erroff, NULL);
    if (!ptr)
    {
        ROLLLOG_ERROR << "Mobile phone number regular expression error" << endl;
        return false;
    }

    int offset[64];
    int ret = pcre_exec(ptr, NULL, str.c_str(), str.length(), 0, 0, offset, sizeof(offset));
    if (ret < 0)
    {
        ROLLLOG_ERROR << "Mobile phone number matching failed, ret=" << ret << endl;
        pcre_free(ptr);
        return false;
    }

    ROLLLOG_DEBUG << "Mobile phone number matched successfully" << endl;
    pcre_free(ptr);
    return true;
}

//替换指定字符串
static std::string replace( const std::string &inStr, const char *pSrc, const char *pReplace )
{
    std::string str = inStr;
    std::string::size_type stStart = 0;
    std::string::iterator iter = str.begin();
    while (iter != str.end())
    {
        // 从指定位置 查找下一个要替换的字符串的起始位置。
        std::string::size_type st = str.find( pSrc, stStart );
        if ( st == str.npos )
            break;

        iter = iter + st - stStart;
        // 将目标字符串全部替换。
        str.replace( iter, iter + strlen( pSrc ), pReplace );
        iter = iter + strlen( pReplace );
        // 替换的字符串下一个字符的位置
        stStart = st + strlen( pReplace );
    }

    return str;
}

// 用户认证信息
static tars::Int32 userAuth(const DBAgentServantPrx prx, const userinfo::UserAuthReq &req, userinfo::UserAuthResp &resp)
{
    int iRet = 0;
    FUNC_ENTRY("");
    __TRY__

    if (prx)
    {
        dataproxy::TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_ACCOUNT) + ":" + L2S(req.uid);
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
        dataReq.clusterInfo.frageFactor = tars::hash<string>()(L2S(req.uid));

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        tfield.colType = BIGINT;
        fields.push_back(tfield);
        tfield.colName = "username";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "password";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "safes_password";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_type";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "reg_time";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_ip";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_device_no";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "is_robot";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "agcid";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "disabled";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "device_id";
        tfield.colType = dbagent::STRING;
        fields.push_back(tfield);
        tfield.colName = "device_type";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "platform";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "channel_id";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "area_id";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "is_forbidden";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "forbidden_time";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "bindChannelId";
        tfield.colType = dbagent::INT;
        fields.push_back(tfield);
        tfield.colName = "bindOpenId";
        tfield.colType = dbagent::STRING;
        fields.push_back(tfield);
        tfield.colName = "isinwhitelist";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "whitelisttime";
        tfield.colType = STRING;
        fields.push_back(tfield);
        dataReq.fields = fields;

        TReadDataRsp dataRsp;
        iRet = prx->redisRead(dataReq, dataRsp);
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "get user auth info err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            resp.resultCode = -2;
            return -2;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto itpass = it->begin(); itpass != it->end(); ++itpass)
            {
                if (itpass->colName == "password")
                {
                    resp.password = itpass->colValue;
                    break;
                }
            }
        }

        iRet = 0;
        resp.resultCode = 0;
    }
    else
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        iRet = -3;
        resp.resultCode = -3;
    }

    __CATCH__
    FUNC_EXIT("", iRet);
    return iRet;
}

// 初始化账户
static tars::Int32 initUser(const DBAgentServantPrx prx, const userinfo::InitUserReq &req, userinfo::InitUserResp &resp)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    if ((req.uid <= 0) || (req.userName.length() <= 0) || ((req.reg_type == 0) && (req.isRobot == 0)) || ((req.reg_type < 0) && (req.reg_type > 4)))
    {
        ROLLLOG_ERROR << "param invalid, userinfo:: InitUserReqreq: " << printTars(req) << endl;
        resp.resultCode = -1;
        return -1;
    }

    if (prx)
    {
        dataproxy::TWriteDataReq wdataReq;
        wdataReq.resetDefautlt();
        wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_ACCOUNT) + ":" + L2S(req.uid);
        wdataReq.operateType = E_REDIS_INSERT;
        wdataReq.clusterInfo.resetDefautlt();
        wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
        wdataReq.clusterInfo.frageFactor = tars::hash<string>()(L2S(req.uid));

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(req.uid);
        fields.push_back(tfield);
        tfield.colName = "username";
        tfield.colType = STRING;
        tfield.colValue = req.userName;
        fields.push_back(tfield);
        tfield.colName = "password";
        tfield.colType = STRING;
        tfield.colValue = req.passwd;
        fields.push_back(tfield);
        tfield.colName = "reg_type";
        tfield.colType = INT;
        tfield.colValue = I2S(req.reg_type);
        fields.push_back(tfield);
        tfield.colName = "reg_time";
        tfield.colType = STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetTimeFormat();
        fields.push_back(tfield);
        tfield.colName = "reg_ip";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "reg_device_no";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "device_id";
        tfield.colType = STRING;
        tfield.colValue = req.deviceID;
        fields.push_back(tfield);
        tfield.colName = "device_type";
        tfield.colType = STRING;
        tfield.colValue = req.deviceType;
        fields.push_back(tfield);
        tfield.colName = "platform";
        tfield.colType = INT;
        tfield.colValue = I2S(req.platform);
        fields.push_back(tfield);
        tfield.colName = "channel_id";
        tfield.colType = INT;
        tfield.colValue = I2S(req.channnelID);
        fields.push_back(tfield);
        tfield.colName = "area_id";
        tfield.colType = INT;
        tfield.colValue = I2S(req.areaID);
        fields.push_back(tfield);
        tfield.colName = "safes_password";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "agcid";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "is_robot";
        tfield.colType = INT;
        tfield.colValue = I2S(req.isRobot);
        fields.push_back(tfield);
        tfield.colName = "is_forbidden";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "forbidden_time";
        tfield.colType = STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "bindChannelId";
        tfield.colType = dbagent::INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "bindOpenId";
        tfield.colType = dbagent::STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "isinwhitelist";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "whitelisttime";
        tfield.colType = STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        wdataReq.fields = fields;

        TWriteDataRsp wdataRsp;
        iRet = prx->redisWrite(wdataReq, wdataRsp);
        if (iRet != 0 || wdataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "redisWrite user account failed, req.uid:" << req.uid << ", iRet:" << iRet << ",wdataRsp:" << printTars(wdataRsp) << endl;
            resp.resultCode = -1;
            return -1;
        }

        //userinfo
        wdataReq.resetDefautlt();
        wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_INFO) + ":" + L2S(req.uid);
        wdataReq.operateType = E_REDIS_INSERT;
        wdataReq.clusterInfo.resetDefautlt();
        wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq.clusterInfo.frageFactor = req.uid;

        fields.clear();
        tfield.colName = "uid";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(req.uid);
        fields.push_back(tfield);

        if (req.reg_type == 2)
        {
            string sNickanme;
            if ("" == req.nickName)
            {
                sNickanme = "Facebook" + L2S(req.uid);
            }

            int iGender = 0;
            string sHeadUrl = "";
            if ("" == req.headUrl)
            {
                int gender = rand() % 2 + 1;
                int headId = (gender == 1) ? (rand() % 5 + 1) : (rand() % 5 + 6);
                iGender = gender;
                sHeadUrl = "touxiang_" + I2S(headId) + ".png";
            }

            //facebook
            tfield.colName = "nickname";
            tfield.colType = STRING;
            tfield.colValue = ("" == req.nickName) ? sNickanme : req.nickName;
            fields.push_back(tfield);
            tfield.colName = "head_str";
            tfield.colType = STRING;
            tfield.colValue = ("" == req.headUrl) ? sHeadUrl : req.headUrl;
            fields.push_back(tfield);
            tfield.colName = "gender";
            tfield.colType = INT;
            tfield.colValue =  ("" == req.headUrl) ? I2S(iGender) : I2S(req.gender);
            fields.push_back(tfield);
        }
        else
        {
            if (req.reg_type == 3)
            {
                //apple
                tfield.colName = "nickname";
                tfield.colType = STRING;
                tfield.colValue = "Apple" + L2S(req.uid);
                fields.push_back(tfield);
            }
            else
            {
                //测试账号,游客,机器人
                tfield.colName = "nickname";
                tfield.colType = STRING;
                tfield.colValue = "Guest" + L2S(req.uid);
                fields.push_back(tfield);
            }

            int gender = rand() % 2 + 1;
            int randHead = (gender == 1) ? (rand() % 5 + 1) : (rand() % 5 + 6);
            tfield.colName = "head_str";
            tfield.colType = STRING;
            tfield.colValue = "touxiang_" + I2S(randHead) + ".png";//随机设置头像 touxiang_(1-9).png
            fields.push_back(tfield);
            tfield.colName = "gender";
            tfield.colType = INT;
            tfield.colValue = I2S(gender);
            fields.push_back(tfield);
        }

        tfield.colName = "head_id";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "area_code";
        tfield.colType = INT;
        tfield.colValue = I2S(req.areaID);
        fields.push_back(tfield);
        tfield.colName = "signature";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "ban_invite";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "ban_friend";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "last_login_time";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetTimeFormat();
        fields.push_back(tfield);
        tfield.colName = "last_logout_time";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "lastBankruptRewardTimes";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "lastBankruptResetTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "lastSignInRewardBit";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "lastSignInRewardTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "curOnlineTime";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "curOnlineUpdateTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "curIngameTime";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "curIngameUpdateTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "firstRechargeId";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "noviceRechargeRewardTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "firstRechargeRewardBit";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeRewardTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "lastRechargeId";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "lastRechargeTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "lastRechargeRewardTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "todayRechargeId";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "todayRechargeTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "todayRechargeRewardTime";
        tfield.colType = dbagent::STRING;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "mobile";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "exchangePwd";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "gold";
        tfield.colType = BIGINT;
        tfield.colValue = req.reg_type == 1 ? "500000" : "1000000";
        fields.push_back(tfield);
        tfield.colName = "ticket_num";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "point";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "level";
        tfield.colType = INT;
        tfield.colValue = "1";
        fields.push_back(tfield);
        tfield.colName = "experience";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "new_hand_reward";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "aiPoint";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "aiGameRound";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "is_unlockadvanceinfo";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "limitRechargeId";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "limitRechargeTime";
        tfield.colType = dbagent::STRING;;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        tfield.colName = "superRechargeId";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "superRechargeTime";
        tfield.colType = dbagent::STRING;;
        tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(0);
        fields.push_back(tfield);
        //暂未使用
        tfield.colName = "province_code";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "city_code";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "email";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "realname";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "idc_no";
        tfield.colType = STRING;
        tfield.colValue = "";
        fields.push_back(tfield);
        tfield.colName = "pay_point";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "reward_point";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "room_card";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "diamond";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "safes_gold";
        tfield.colType = BIGINT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "vip_level";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);
        tfield.colName = "vip_experience";
        tfield.colType = INT;
        tfield.colValue = "0";
        tfield.colName = "ban_showdata";
        tfield.colType = INT;
        tfield.colValue = "0";
        fields.push_back(tfield);

        wdataReq.fields = fields;

        iRet = prx->redisWrite(wdataReq, wdataRsp);
        if (iRet != 0 || wdataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "redisWrite tb_userinfo failed, req.uid:" << req.uid << ", iRet:" << iRet
                          << ",wdataRsp:" << printTars(wdataRsp) << ", now delete useraccount record!" << endl;
            // DeleteUserAccount(req.uid);//异常处理:tb_userinfo记录写入失败时,删除tb_useraccount中对应记录
            resp.resultCode = -2;
            return -2;
        }
    }
    else
    {
        ROLLLOG_ERROR << "prx is null" << endl;
        resp.resultCode = -4;
        return -4;
    }

    __CATCH__
    FUNC_EXIT("", iRet);
    return iRet;
}


Processor::Processor()
{

}

Processor::~Processor()
{

}

//查询
int Processor::SelectUserAccount(long uid, userinfo::GetUserResp &rsp)
{
    if (uid <= 0)
    {
        ROLLLOG_ERROR << "invalid uid, uid: " << uid << endl;
        return -1;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(uid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null, uid: " << uid << endl;
        return -1;
    }

    dataproxy::TReadDataReq dataReq;
    dataReq.resetDefautlt();
    dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_ACCOUNT) + ":" + L2S(uid);
    dataReq.operateType = E_REDIS_READ;
    dataReq.clusterInfo.resetDefautlt();
    dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    dataReq.clusterInfo.frageFactor = tars::hash<string>()(L2S(uid));

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "uid";
    tfield.colType = BIGINT;
    fields.push_back(tfield);
    tfield.colName = "username";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "password";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "safes_password";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "reg_type";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "reg_time";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "reg_ip";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "reg_device_no";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "is_robot";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "agcid";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "disabled";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "device_id";
    tfield.colType = dbagent::STRING;
    fields.push_back(tfield);
    tfield.colName = "device_type";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "platform";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "channel_id";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "area_id";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "is_forbidden";
    tfield.colType = INT;
    fields.push_back(tfield);
    tfield.colName = "forbidden_time";
    tfield.colType = STRING;
    fields.push_back(tfield);
    tfield.colName = "bindChannelId";
    tfield.colType = dbagent::INT;
    fields.push_back(tfield);
    tfield.colName = "bindOpenId";
    tfield.colType = dbagent::STRING;
    fields.push_back(tfield);
    tfield.colName = "isinwhitelist";
    tfield.colType = dbagent::INT;
    fields.push_back(tfield);
    tfield.colName = "whitelisttime";
    tfield.colType = dbagent::STRING;
    fields.push_back(tfield);
    dataReq.fields = fields;

    dataproxy::TReadDataRsp dataRsp;
    int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
    if ((iRet != 0) || (dataRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "redisRead failed, iRet: " << iRet << ", dataRsp.iResult: " << dataRsp.iResult << endl;
        return -2;
    }

    if (dataRsp.fields.empty())
    {
        ROLLLOG_ERROR << "uid:" << uid << " not exist in tb_useraccount!" << endl;
        return -3;
    }

    for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
    {
        for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
        {
            ROLLLOG_DEBUG << "read user account, colName: " << itfields->colName << ", colValue: " << itfields->colValue << endl;

            if (itfields->colName == "username")
            {
                rsp.userName = itfields->colValue;
            }
            else if (itfields->colName == "device_id")
            {
                rsp.deviceID = itfields->colValue;
            }
            else if (itfields->colName == "device_type")
            {
                rsp.deviceType = itfields->colValue;
            }
            else if (itfields->colName == "platform")
            {
                rsp.platform = (userinfo::E_Platform_Type)S2I(itfields->colValue);
            }
            else if (itfields->colName == "channel_id")
            {
                rsp.channnelID = (userinfo::E_Channel_ID)S2I(itfields->colValue);
            }
            else if (itfields->colName == "area_id")
            {
                rsp.areaID = S2I(itfields->colValue);
            }
            else if (itfields->colName == "is_robot")
            {
                rsp.isRobot = S2I(itfields->colValue);
            }
            else if (itfields->colName == "reg_time")
            {
                rsp.regTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfields->colValue);
            }
            else if (itfields->colName == "bindChannelId")
            {
                rsp.bindChannelId = S2I(itfields->colValue);
            }
            else if (itfields->colName == "bindOpenId")
            {
                rsp.bindOpenId = itfields->colValue;
            }
            else if (itfields->colName == "isinwhitelist")
            {
                rsp.isinwhitelist = S2I(itfields->colValue);
            }
            else if (itfields->colName == "whitelisttime")
            {
                rsp.whitelisttime = g_app.getOuterFactoryPtr()->GetTimeTick(itfields->colValue);
            }
        }
    }

    ROLLLOG_DEBUG << "get useraccount data succ: uid= " << uid << ", fields size: " << dataRsp.fields.size() << endl;
    return 0;
}

//查询
int Processor::SelectUserInfo(long uid, userinfo::GetUserBasicResp &rsp)
{
    if (uid <= 0)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null: uid: " << uid << endl;
        return -1;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(uid);
    if (pDBAgentServant)
    {
        TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_INFO) + ":" + L2S(uid);
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = uid;

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        fields.push_back(tfield);
        tfield.colName = "nickname";
        fields.push_back(tfield);
        tfield.colName = "head_id";
        fields.push_back(tfield);
        tfield.colName = "head_str";
        fields.push_back(tfield);
        tfield.colName = "gender";
        fields.push_back(tfield);
        tfield.colName = "area_code";
        fields.push_back(tfield);
        tfield.colName = "signature";
        fields.push_back(tfield);
        tfield.colName = "ban_invite";
        fields.push_back(tfield);
        tfield.colName = "ban_friend";
        fields.push_back(tfield);
        tfield.colName = "last_login_time";
        fields.push_back(tfield);
        tfield.colName = "last_logout_time";
        fields.push_back(tfield);
        tfield.colName = "lastBankruptRewardTimes";
        fields.push_back(tfield);
        tfield.colName = "lastBankruptResetTime";
        fields.push_back(tfield);
        tfield.colName = "lastSignInRewardBit";
        fields.push_back(tfield);
        tfield.colName = "lastSignInRewardTime";
        fields.push_back(tfield);
        tfield.colName = "curOnlineTime";
        fields.push_back(tfield);
        tfield.colName = "curOnlineUpdateTime";
        fields.push_back(tfield);
        tfield.colName = "curIngameTime";
        fields.push_back(tfield);
        tfield.colName = "curIngameUpdateTime";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeId";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeTime";
        fields.push_back(tfield);
        tfield.colName = "noviceRechargeRewardTime";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeRewardBit";
        fields.push_back(tfield);
        tfield.colName = "firstRechargeRewardTime";
        fields.push_back(tfield);
        tfield.colName = "lastRechargeId";
        fields.push_back(tfield);
        tfield.colName = "lastRechargeTime";
        fields.push_back(tfield);
        tfield.colName = "lastRechargeRewardTime";
        fields.push_back(tfield);
        tfield.colName = "todayRechargeId";
        fields.push_back(tfield);
        tfield.colName = "todayRechargeTime";
        fields.push_back(tfield);
        tfield.colName = "todayRechargeRewardTime";
        fields.push_back(tfield);
        tfield.colName = "mobile";
        fields.push_back(tfield);
        tfield.colName = "exchangePwd";
        fields.push_back(tfield);

        tfield.colName = "gold";
        fields.push_back(tfield);
        tfield.colName = "ticket_num";
        fields.push_back(tfield);
        tfield.colName = "point";
        fields.push_back(tfield);
        tfield.colName = "level";
        fields.push_back(tfield);
        tfield.colName = "experience";
        fields.push_back(tfield);

        //暂未使用
        tfield.colName = "province_code";
        fields.push_back(tfield);
        tfield.colName = "city_code";
        fields.push_back(tfield);
        tfield.colName = "email";
        fields.push_back(tfield);
        tfield.colName = "realname";
        fields.push_back(tfield);
        tfield.colName = "idc_no";
        fields.push_back(tfield);
        tfield.colName = "pay_point";
        fields.push_back(tfield);
        tfield.colName = "reward_point";
        fields.push_back(tfield);
        tfield.colName = "room_card";
        fields.push_back(tfield);
        tfield.colName = "diamond";
        fields.push_back(tfield);
        tfield.colName = "safes_gold";
        fields.push_back(tfield);
        tfield.colName = "vip_level";
        fields.push_back(tfield);
        tfield.colName = "vip_experience";
        fields.push_back(tfield);
        tfield.colName = "new_hand_reward";
        fields.push_back(tfield);
        tfield.colName = "aiPoint";
        fields.push_back(tfield);
        tfield.colName = "aiGameRound";
        fields.push_back(tfield);
        tfield.colName = "is_unlockadvanceinfo";
        fields.push_back(tfield);
        tfield.colName = "limitRechargeId";
        fields.push_back(tfield);
        tfield.colName = "limitRechargeTime";
        fields.push_back(tfield);
        tfield.colName = "superRechargeId";
        fields.push_back(tfield);
        tfield.colName = "superRechargeTime";
        fields.push_back(tfield);
        dataReq.fields = fields;

        dataproxy::TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        if ((iRet != 0) || (dataRsp.iResult != 0))
        {
            ROLLLOG_ERROR << "redisRead failed, iRet: " << iRet << ", dataRsp.iResult: " << dataRsp.iResult << endl;
            return -1;
        }

        if (dataRsp.fields.empty())
        {
            ROLLLOG_ERROR << "uid:" << uid << " not exist in db!" << endl;
            return -1;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto itfield = it->begin(); itfield != it->end(); ++itfield)
            {
                if (itfield->colName == "nickname")
                {
                    rsp.name = itfield->colValue;
                }
                else if (itfield->colName == "head_str")
                {
                    rsp.head = itfield->colValue;
                }
                else if (itfield->colName == "gender")
                {
                    int iGender = S2I(itfield->colValue);
                    rsp.gender = (iGender > 0) ? iGender : 1;
                }
                else if (itfield->colName == "area_code")
                {
                    rsp.areaCode = S2I(itfield->colValue);
                }
                else if (itfield->colName == "signature")
                {
                    rsp.signature = itfield->colValue;
                }
                else if (itfield->colName == "ban_invite")
                {
                    rsp.banInvite = S2I(itfield->colValue);
                }
                else if (itfield->colName == "ban_friend")
                {
                    rsp.banFriend = S2I(itfield->colValue);
                }
                else if (itfield->colName == "last_login_time")
                {
                    rsp.lastLoginTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "last_logout_time")
                {
                    rsp.lastLogoutTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "lastBankruptRewardTimes")
                {
                    rsp.lastBankruptRewardTimes = S2I(itfield->colValue);
                }
                else if (itfield->colName == "lastBankruptResetTime")
                {
                    rsp.lastBankruptResetTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "lastSignInRewardBit")
                {
                    rsp.lastSignInRewardBit = itfield->colValue;
                }
                else if (itfield->colName == "lastSignInRewardTime")
                {
                    rsp.lastSignInRewardTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "curOnlineTime")
                {
                    rsp.curOnlineTime = S2I(itfield->colValue);
                }
                else if (itfield->colName == "curOnlineUpdateTime")
                {
                    rsp.curOnlineUpdateTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "curIngameTime")
                {
                    rsp.curIngameTime = S2I(itfield->colValue);
                }
                else if (itfield->colName == "curIngameUpdateTime")
                {
                    rsp.curIngameUpdateTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "firstRechargeId")
                {
                    rsp.firstRechargeId = S2I(itfield->colValue);
                }
                else if (itfield->colName == "firstRechargeTime")
                {
                    rsp.firstRechargeTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "noviceRechargeRewardTime")
                {
                    rsp.noviceRechargeRewardTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "firstRechargeRewardBit")
                {
                    rsp.firstRechargeRewardBit = itfield->colValue;
                }
                else if (itfield->colName == "firstRechargeRewardTime")
                {
                    rsp.firstRechargeRewardTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "lastRechargeId")
                {
                    rsp.lastRechargeId = S2I(itfield->colValue);
                }
                else if (itfield->colName == "lastRechargeTime")
                {
                    rsp.lastRechargeTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "lastRechargeRewardTime")
                {
                    rsp.lastRechargeRewardTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "todayRechargeId")
                {
                    rsp.todayRechargeId = S2I(itfield->colValue);
                }
                else if (itfield->colName == "todayRechargeTime")
                {
                    rsp.todayRechargeTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "todayRechargeRewardTime")
                {
                    rsp.todayRechargeRewardTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "mobile")
                {
                    rsp.mobile = itfield->colValue;
                }
                else if (itfield->colName == "exchangePwd")
                {
                    rsp.exchangePwd = itfield->colValue;
                }
                else if (itfield->colName == "gold")
                {
                    rsp.gold = S2L(itfield->colValue);
                }
                else if (itfield->colName == "ticket_num")
                {
                    rsp.ticketNum = S2L(itfield->colValue);
                }
                else if (itfield->colName == "point")
                {
                    rsp.point = S2L(itfield->colValue);
                }
                else if (itfield->colName == "level")
                {
                    rsp.level = S2I(itfield->colValue);
                }
                else if (itfield->colName == "experience")
                {
                    rsp.experience = S2I(itfield->colValue);
                }
                else if (itfield->colName == "pay_point")
                {
                    rsp.payPoint = S2L(itfield->colValue);
                }
                else if (itfield->colName == "reward_point")
                {
                    rsp.rewardPoint = S2L(itfield->colValue);
                }
                else if (itfield->colName == "room_card")
                {
                    rsp.roomCard = S2L(itfield->colValue);
                }
                else if (itfield->colName == "diamond")
                {
                    rsp.diamond = S2L(itfield->colValue);
                }
                else if (itfield->colName == "safes_gold")
                {
                    rsp.safeGold = S2L(itfield->colValue);
                }
                else if (itfield->colName == "is_unlockadvanceinfo")
                {
                    rsp.is_unlockadvanceinfo = S2I(itfield->colValue);
                }
                else if (itfield->colName == "limitRechargeId")
                {
                    rsp.limitRechargeId = S2I(itfield->colValue);
                }
                else if (itfield->colName == "limitRechargeTime")
                {
                    rsp.limitRechargeTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
                else if (itfield->colName == "superRechargeId")
                {
                    rsp.superRechargeId = S2I(itfield->colValue);
                }
                else if (itfield->colName == "superRechargeTime")
                {
                    rsp.superRechargeTime = g_app.getOuterFactoryPtr()->GetTimeTick(itfield->colValue);
                }
            }
        }

        ROLLLOG_DEBUG << "get userinfo data succ: uid: " << uid << endl;
    }
    else
    {
        ROLLLOG_ERROR << "pDBAgentServant is null: uid: " << uid << endl;
        return -2;
    }

    return 0;
}

// 更新用户第三方信息
int Processor::UpdateUserThirdInfo(const userinfo::UpdateUserInfoReq &req, userinfo::UpdateUserInfoResp &rsp)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid);
    if (pDBAgentServant)
    {
        dataproxy::TWriteDataReq wdataReq;
        wdataReq.resetDefautlt();
        wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_INFO) + ":" + L2S(req.uid);
        wdataReq.operateType = E_REDIS_WRITE;
        wdataReq.clusterInfo.resetDefautlt();
        wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq.clusterInfo.frageFactor = req.uid;

        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "nickname";
        tfield.colType = STRING;
        tfield.colValue = req.nickname;
        wdataReq.fields.push_back(tfield);
        tfield.colName = "head_id";
        tfield.colType = INT;
        tfield.colValue = I2S(req.head_id);
        wdataReq.fields.push_back(tfield);
        tfield.colName = "head_str";
        tfield.colType = STRING;
        tfield.colValue = req.head_url;
        wdataReq.fields.push_back(tfield);
        tfield.colName = "gender";
        tfield.colType = INT;
        tfield.colValue = I2S(req.gender);
        wdataReq.fields.push_back(tfield);
        tfield.colName = "signature";
        tfield.colType = STRING;
        tfield.colValue = req.signature;
        wdataReq.fields.push_back(tfield);

        TWriteDataRsp wdataRsp;
        iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
        ROLLLOG_DEBUG << "set user info, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
        if (iRet != 0 || wdataRsp.iResult != 0)
        {
            rsp.resultCode = -1;
            return -1;
        }
    }
    else
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        rsp.resultCode = -2;
        return -2;
    }

    __CATCH__
    FUNC_EXIT("", iRet);
    return iRet;
}

//账号登录处理
int Processor::UserLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo)
{
    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username len: " << req.username() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //uid不合法
    if (getRegisterRsp.lUid <= 0)
    {
        ROLLLOG_ERROR << "getRegisterRsp.lUid err, lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //用uid查找密码
    UserAuthReq userAuthReq;
    userAuthReq.uid = getRegisterRsp.lUid;
    UserAuthResp userAuthResp;
    iRet = userAuth(pDBAgentServant, userAuthReq, userAuthResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user auth error, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (req.passwd() != userAuthResp.password)
    {
        ROLLLOG_ERROR << "password error, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    //生成token,并保存
    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(getRegisterRsp.lUid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = getRegisterRsp.lUid;

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = strToken;
    fields.push_back(tfield);
    tfield.colName = "exptime";
    tfield.colType = BIGINT;
    tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tfield);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    if (iRet != 0 || wdataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    //登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));              //AppId|DB_STR
    vLogLogin.push_back("1001");                   //GameId|DB_STR
    vLogLogin.push_back("0");                      //ChannelId|DB_STR
    vLogLogin.push_back("0");                      //AreaId|DB_STR
    vLogLogin.push_back("0");                      //Platform|DB_STR
    vLogLogin.push_back(L2S(getRegisterRsp.lUid)); //Uuid|DB_STR
    vLogLogin.push_back("");                       //DeviceId|DB_STR
    vLogLogin.push_back(sRemoteIp);                //Ip|DB_STR
    vLogLogin.push_back("1");                      //OperationCode|DB_STR
    vLogLogin.push_back("0");                      //OnlineTime|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(getRegisterRsp.lUid, 21, vLogLogin);

    rsp.set_resultcode(0);
    rsp.set_uid(getRegisterRsp.lUid);
    rsp.set_token(strToken);
    return 0;
}

//登出
int Processor::UserLogout(const LoginProto::LogoutReq &req, LoginProto::LogoutResp &rsp, bool sysOp, string ip)
{
    if (req.uid() < 0)
    {
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //读取token
    string exptime = "";
    string device_id = "";
    string platform = "";
    string channel_id = "";
    string area_id = "";
    string reg_ip = "";

    //获取登录密钥
    if (true)
    {
        dataproxy::TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.uid();

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        fields.push_back(tfield);
        tfield.colName = "exptime";
        fields.push_back(tfield);
        dataReq.fields = fields;

        TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        ROLLLOG_DEBUG << "read user token data, iRet: " << iRet << ", datareq: " << printTars(dataReq) << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "read user token err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
            {
                if (itfields->colName == "exptime")
                {
                    exptime = itfields->colValue;
                    break;
                }
            }
        }
    }

    //更新帐户资料
    if (true)
    {
        TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_ACCOUNT) + ":" + L2S(req.uid());
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
        dataReq.clusterInfo.frageFactor = tars::hash<string>()(L2S(req.uid()));

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "uid";
        tfield.colType = BIGINT;
        fields.push_back(tfield);
        tfield.colName = "username";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "password";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "safes_password";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_type";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "reg_time";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_ip";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "reg_device_no";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "is_robot";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "agcid";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "disabled";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "device_id";
        tfield.colType = dbagent::STRING;
        fields.push_back(tfield);
        tfield.colName = "device_type";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "platform";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "channel_id";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "area_id";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "is_forbidden";
        tfield.colType = INT;
        fields.push_back(tfield);
        tfield.colName = "forbidden_time";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "bindChannelId";
        tfield.colType = dbagent::INT;
        fields.push_back(tfield);
        tfield.colName = "bindOpenId";
        tfield.colType = dbagent::STRING;
        fields.push_back(tfield);
        tfield.colName = "isinwhitelist";
        tfield.colType = dbagent::INT;
        fields.push_back(tfield);
        tfield.colName = "whitelisttime";
        tfield.colType = dbagent::STRING;
        fields.push_back(tfield);
        dataReq.fields = fields;

        dataproxy::TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "get user-account failed, uid: " << req.uid() << ", iResult: " << dataRsp.iResult << endl;
            return -2;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
            {
                ROLLLOG_DEBUG << "read user account, colName: " << itfields->colName << ", colValue: " << itfields->colValue << endl;

                if (itfields->colName == "device_id")
                    device_id = itfields->colValue;
                else if (itfields->colName == "platform")
                    platform = itfields->colValue;
                else if (itfields->colName == "channel_id")
                    channel_id = itfields->colValue;
                else if (itfields->colName == "area_id")
                    area_id = itfields->colValue;
                else if (itfields->colName == "reg_ip")
                    reg_ip = itfields->colValue;
            }
        }
    }

    //删除token
    if (true)
    {
        dataproxy::TWriteDataRsp dataRsp;
        dataproxy::TWriteDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
        dataReq.operateType = E_REDIS_DELETE;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.uid();
        int iRet = pDBAgentServant->redisWrite(dataReq, dataRsp);
        ROLLLOG_DEBUG << "delete user token data, iRet: " << iRet << ", datareq: " << printTars(dataReq) << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "delete user token err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }
    }

    //用户登出日志
    if (true)
    {
        long loginTime = time(NULL) - (S2L(exptime) - TOKEN_EXPTIME);
        if (loginTime < 0)
        {
            loginTime = 0;
        }

        vector<string> vLogLogout;
        vLogLogout.push_back(I2S(APP_ID));
        vLogLogout.push_back("1001");
        vLogLogout.push_back(channel_id);
        vLogLogout.push_back(area_id);
        vLogLogout.push_back(platform.empty() ? "0" : platform);
        vLogLogout.push_back(L2S(req.uid()));
        vLogLogout.push_back(device_id);
        vLogLogout.push_back(reg_ip);
        vLogLogout.push_back("2");
        vLogLogout.push_back(L2S(loginTime));
        g_app.getOuterFactoryPtr()->asyncLog2DB(req.uid(), 21, vLogLogout);
    }

    rsp.set_resultcode(0);
    return 0;
}

//游客登录
int Processor::DeviceLogin(const LoginProto::DeviceLoginReq &req, LoginProto::DeviceLoginResp &rsp, const map<string, string> &extraInfo)
{
    if (req.deviceno().length() <= 0)
    {
        ROLLLOG_ERROR << "parameter empty, device num len: " << req.deviceno().length() << ", ret: -1" << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.deviceno());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.deviceno();

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "DeviceLogin info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "DeviceLogin info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //login token
    string strToken = generateUUIDStr();
    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    vector<TField> fields;
    TField tfield;
    tfield.colArithType = E_NONE;
    if (getRegisterRsp.lUid > 0)
    {
        //生成登录密钥
        TWriteDataReq wdataReq2;
        TWriteDataRsp wdataRsp2;
        wdataReq2.resetDefautlt();
        wdataReq2.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(getRegisterRsp.lUid);
        wdataReq2.operateType = E_REDIS_WRITE;
        wdataReq2.clusterInfo.resetDefautlt();
        wdataReq2.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq2.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq2.clusterInfo.frageFactor = getRegisterRsp.lUid;

        fields.clear();
        tfield.colName = "token";
        tfield.colType = STRING;
        tfield.colValue = strToken;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
        fields.push_back(tfield);
        wdataReq2.fields = fields;
        iRet = pDBAgentServant->redisWrite(wdataReq2, wdataRsp2);
        ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp2: " << printTars(wdataRsp2) << endl;
        if (iRet != 0 || wdataRsp2.iResult != 0)
        {
            ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp2.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //用户登录日志
        vector<string> vLogLogin;
        vLogLogin.push_back(I2S(APP_ID));
        vLogLogin.push_back("1001");
        vLogLogin.push_back(I2S((int)req.channnelid()));
        vLogLogin.push_back(I2S(req.areaid()));
        vLogLogin.push_back(I2S((int)req.platform()));
        vLogLogin.push_back(L2S(getRegisterRsp.lUid));
        vLogLogin.push_back(req.deviceid());
        vLogLogin.push_back(sRemoteIp);
        vLogLogin.push_back("1");
        vLogLogin.push_back("0");
        g_app.getOuterFactoryPtr()->asyncLog2DB(getRegisterRsp.lUid, 21, vLogLogin);

        //登录反馈信息
        rsp.set_resultcode(0);
        rsp.set_uid(getRegisterRsp.lUid);
        rsp.set_token(strToken);
        rsp.set_flag(0);
        LOG_DEBUG << "DeviceLogin success(1), uid: " << getRegisterRsp.lUid << ", deviceNo: " << req.deviceno() << endl;
        return XGameRetCode::SUCCESS;
    }
    else
    {
        //生成用户标识
        TGetTableGUIDRsp insertIDRsp;
        TGetTableGUIDReq insertIDReq;
        insertIDReq.keyIndex = 0;
        insertIDReq.tableName = "tb_uid_guid";
        insertIDReq.fieldName = "uid";
        iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
        ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
        if (insertIDRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //注册帐号
        userinfo::InitUserResp initUserResp;
        userinfo::InitUserReq initUserReq;
        initUserReq.uid = insertIDRsp.lastID;
        initUserReq.userName = req.deviceno();
        initUserReq.passwd = "123456";
        initUserReq.deviceID = req.deviceid();
        initUserReq.deviceType = req.devicetype();
        initUserReq.platform = (userinfo::E_Platform_Type)((int)req.platform());
        initUserReq.channnelID = (userinfo::E_Channel_ID)((int)req.channnelid());
        initUserReq.areaID = (req.areaid() <= 0) ? 86 : req.areaid();
        initUserReq.isRobot = 0;
        initUserReq.reg_type = 1;//游客
        iRet = initUser(pDBAgentServant, initUserReq, initUserResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //注册日志
        vector<string> vLogRegister;
        vLogRegister.push_back(I2S(APP_ID));                   //AppId|DB_STR
        vLogRegister.push_back("1001");                        //GameId|DB_STR
        vLogRegister.push_back(I2S(initUserReq.channnelID));   //ChannelId|DB_STR
        vLogRegister.push_back("0");                           //AreaId|DB_STR
        vLogRegister.push_back(I2S(initUserReq.platform));     //Platform|DB_STR
        vLogRegister.push_back(L2S(initUserReq.uid));          //Uuid|DB_STR
        vLogRegister.push_back(initUserReq.userName);          //UserAccount|DB_STR
        vLogRegister.push_back(initUserReq.deviceID);          //DeviceId|DB_STR
        vLogRegister.push_back(initUserReq.deviceType);        //DeviceType|DB_STR
        vLogRegister.push_back(sRemoteIp);                     //Ip|DB_STR
        g_app.getOuterFactoryPtr()->asyncLog2DB(initUserReq.uid, 20, vLogRegister);

        //生成登录密钥
        TWriteDataReq wdataReq2;
        TWriteDataRsp wdataRsp2;
        wdataReq2.resetDefautlt();
        wdataReq2.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(insertIDRsp.lastID);
        wdataReq2.operateType = E_REDIS_WRITE;
        wdataReq2.clusterInfo.resetDefautlt();
        wdataReq2.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq2.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq2.clusterInfo.frageFactor = insertIDRsp.lastID;

        fields.clear();
        tfield.colName = "token";
        tfield.colType = STRING;
        tfield.colValue = strToken;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
        fields.push_back(tfield);
        wdataReq2.fields = fields;
        iRet = pDBAgentServant->redisWrite(wdataReq2, wdataRsp2);
        ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp2: " << printTars(wdataRsp2) << endl;
        if (iRet != 0 || wdataRsp2.iResult != 0)
        {
            ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp2.iResult << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //用户登录日志
        vector<string> vLogLogin;
        vLogLogin.push_back(I2S(APP_ID));
        vLogLogin.push_back("1001");
        vLogLogin.push_back(I2S((int)req.channnelid()));
        vLogLogin.push_back(I2S(req.areaid()));
        vLogLogin.push_back(I2S((int)req.platform()));
        vLogLogin.push_back(L2S(initUserReq.uid));
        vLogLogin.push_back(req.deviceid());
        vLogLogin.push_back(sRemoteIp);
        vLogLogin.push_back("1");
        vLogLogin.push_back("0");
        g_app.getOuterFactoryPtr()->asyncLog2DB(initUserReq.uid, 21, vLogLogin);

        //登录反馈消息
        rsp.set_resultcode(0);
        rsp.set_uid(insertIDRsp.lastID);
        rsp.set_token(strToken);
        rsp.set_flag(1);
        LOG_DEBUG << "DeviceLogin success(2), uid: " << getRegisterRsp.lUid << ", deviceNo: " << req.deviceno() << endl;
        return XGameRetCode::SUCCESS;
    }
}

int Processor::QuickLogin(const LoginProto::QuickLoginReq &req, LoginProto::QuickLoginResp &rsp, const map<string, string> &extraInfo)
{
    int iRet = 0;
    if (req.token().length() <= 0 || req.uid() <= 0)
    {
        ROLLLOG_ERROR << "parameter empty, token : " << req.token() << ", uid:" << req.uid() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TReadDataReq dataReq;
    dataReq.resetDefautlt();
    dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
    dataReq.operateType = E_REDIS_READ;
    dataReq.clusterInfo.resetDefautlt();
    dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    dataReq.clusterInfo.frageFactor = req.uid();

    vector<TField> fields;

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    fields.push_back(tfield);
    tfield.colName = "exptime";
    fields.push_back(tfield);
    dataReq.fields = fields;

    dataproxy::TReadDataRsp dataRsp;
    iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
    if (iRet != 0)
    {
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    std::string token;
    long exptime = 0;
    for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
    {
        for (auto itfield = it->begin(); itfield != it->end(); ++itfield)
        {
            if (itfield->colName == "exptime")
            {
                exptime = S2L(itfield->colValue);
            }
            else if (itfield->colName == "token")
            {
                token = itfield->colValue;
            }
        }
    }

    if (token != req.token())
    {
        ROLLLOG_ERROR << "uid:" << req.uid() << "token not equal. in token: " << token << ", out token :" << req.token() << endl;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    if (exptime < time(NULL))
    {
        ROLLLOG_ERROR << "token is expired. exptime " << exptime << ", now :" << time(NULL) << endl;
        return XGameRetCode::LOGIN_TOKEN_EXPIRED;
    }

    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.uid());
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = req.uid();

    fields.clear();
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = strToken;
    fields.push_back(tfield);
    tfield.colName = "exptime";
    tfield.colType = BIGINT;
    tfield.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tfield);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    if (iRet != 0 || dataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    rsp.set_uid(req.uid());
    rsp.set_token(strToken);
    rsp.set_flag(0);
    return iRet;
}

int Processor::ThirdPartyLogin(const LoginProto::ThirdPartyLoginReq &req, LoginProto::ThirdPartyLoginResp &rsp, const map<string, string> &extraInfo)
{
    bool isGoogle = (req.logintype() == LoginProto::E_LOGIN_TYPE::E_LOGIN_GOOGLE);
    bool isFaceBook = (req.logintype() == LoginProto::E_LOGIN_TYPE::E_LOGIN_FACEBOOK);
    bool isApple = (req.logintype() == LoginProto::E_LOGIN_TYPE::E_LOGIN_APPLE);
    if ((req.openid().length() <= 0) || (!isGoogle && !isFaceBook && !isApple))
    {
        ROLLLOG_ERROR << "ThirdParty info invalid, openid: " << req.openid().length() << ", logintype: " << req.logintype() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.openid());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "req:" << logPb(req) << endl;

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;


    int iRet = -1;
    userinfo::UpdateUserInfoReq thirdInfoReq;
    if (isGoogle)
        iRet = getUserInfoFromGoogle(req.token(), req.openid(), thirdInfoReq);
    else if (isFaceBook)
        iRet = getUserInfoFromFacebook(req.token(), thirdInfoReq);
    else if (isApple)
        iRet = getUserInfoFromApple(req.token(), thirdInfoReq);
    else
        ROLLLOG_ERROR << "login type err. type :" << req.logintype()  << endl;

    if (0 != iRet)
    {
        ROLLLOG_ERROR << "thirdparty err. iRet:" << iRet  << ",loginType:" << req.logintype() << endl;
        return iRet;
    }

    //账号是否存在
    std::string openid = "";
    int iRegType = 0;
    if (isGoogle)
    {
        openid = "Google_" + req.openid();
        iRegType = 4;
    }
    else if (isFaceBook)
    {
        openid = "FB_" + req.openid();
        iRegType = 2;
    }
    else if (isApple)
    {
        openid = "Apple_" + req.openid();
        iRegType = 3;
    }
    else
    {
        ROLLLOG_ERROR << "logintype err. type:" << (LoginProto::E_LOGIN_TYPE)req.logintype() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //查找帐号标识
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = openid;
    getRegisterReq.iThirdParty = 1;

    TGetRegisterInfoRsp getRegisterRsp;
    iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "thirdparty register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "thirdparty register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        rsp.set_resultcode(-1003);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取用户标识
    bool bNewUser = false;
    tars::Int64 uid = getRegisterRsp.lUid;
    if (uid <= 0)
    {
        LoginProto::RegisterReq regReq;
        regReq.set_username(openid);
        regReq.set_passwd(openid);
        regReq.set_deviceid(req.deviceno());
        regReq.set_devicetype(req.deviceno());
        regReq.set_platform(req.platform());
        regReq.set_channnelid(req.channnelid());
        regReq.set_areaid((req.areaid() <= 0) ? 86 : req.areaid());

        LoginProto::RegisterResp regRsp;
        iRet = ThirdRegister(regReq, regRsp, thirdInfoReq, iRegType, sRemoteIp);
        if (iRet != 0 && regRsp.resultcode() != 0)
        {
            ROLLLOG_ERROR << "username not exist, iRet: " << iRet << ", resultcode: " << regRsp.resultcode() << endl;
            rsp.set_resultcode(-1014);
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        bNewUser = true;
        uid = regRsp.uid();
    }

    //uid不合法
    if (uid <= 0)
    {
        ROLLLOG_ERROR << "uid err, uid: " << uid << endl;
        rsp.set_resultcode(-1005);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //需要实现黑白名单功能
    UserAuthReq userAuthReq;
    userAuthReq.uid = uid;
    UserAuthResp userAuthResp;
    iRet = userAuth(pDBAgentServant, userAuthReq, userAuthResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user auth error, iRet: " << iRet << endl;
        rsp.set_resultcode(-1008);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //第三方账号注册首次登录的账号,才进行密码校验
    if ((getRegisterRsp.bindChannelId == 0) && (openid != userAuthResp.password))
    {
        ROLLLOG_ERROR << "password error, iRet: " << iRet << ", reqPass: " << openid << ", password: " << userAuthResp.password << endl;
        rsp.set_resultcode(-1009);
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(uid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = uid;

    vector<TField> fields;
    TField tField;
    tField.colArithType = E_NONE;
    tField.colName = "token";
    tField.colType = STRING;
    tField.colValue = strToken;
    fields.push_back(tField);
    tField.colName = "exptime";
    tField.colType = BIGINT;
    tField.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tField);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    if (iRet != 0 || wdataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (bNewUser && (iRegType == 2) && !thirdInfoReq.nickname.empty())
        // if ((iRegType == 2) && !thirdInfoReq.nickname.empty())
    {
        //facebook账号注册,首次登录时,使用fb社区昵称和头像等信息
        userinfo::GetUserBasicResp getUserBasicResp;
        iRet = SelectUserInfo(uid, getUserBasicResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "SelectUserInfo() fail, uid: " << uid << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        //更新头像信息
        thirdInfoReq.uid = uid;
        userinfo::UpdateUserInfoResp updateUserInfoResp;
        iRet = UpdateUserThirdInfo(thirdInfoReq, updateUserInfoResp);
        if (iRet != 0)
        {
            ROLLLOG_ERROR << "update user info err, iRet: " << iRet << endl;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }
    }

    //登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));           //AppId|DB_STR
    vLogLogin.push_back("1001");                //GameId|DB_STR
    vLogLogin.push_back(I2S(req.channnelid())); //ChannelId|DB_STR
    vLogLogin.push_back("0");                   //AreaId|DB_STR
    vLogLogin.push_back(I2S(req.platform()));   //Platform|DB_STR
    vLogLogin.push_back(L2S(uid));              //Uuid|DB_STR
    vLogLogin.push_back(req.deviceno());        //DeviceId|DB_STR
    vLogLogin.push_back(sRemoteIp);             //Ip|DB_STR
    vLogLogin.push_back("1");                   //OperationCode|DB_STR
    vLogLogin.push_back("0");                   //OnlineTime|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(uid, 21, vLogLogin);

    rsp.set_uid(uid);
    rsp.set_token(strToken);
    rsp.set_flag(bNewUser ? 1 : 0);
    return iRet;
}

//账号注册处理
int Processor::UserRegister(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const string &ip)
{
    int iRet = 0;
    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username: " << req.username() << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();

    TGetRegisterInfoRsp getRegisterRsp;
    iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (getRegisterRsp.lUid > 0)
    {
        ROLLLOG_ERROR << "username exist, getRegisterRsp.lUid: " << getRegisterRsp.lUid << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取新uid
    TGetTableGUIDReq insertIDReq;
    insertIDReq.keyIndex = 0;
    insertIDReq.tableName = "tb_uid_guid";
    insertIDReq.fieldName = "uid";

    TGetTableGUIDRsp insertIDRsp;
    iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
    ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
    if (insertIDRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册基本信息
    InitUserReq initUserReq;
    initUserReq.uid = insertIDRsp.lastID;
    initUserReq.userName = req.username();
    initUserReq.passwd = req.passwd();
    initUserReq.deviceID = req.deviceid();
    initUserReq.deviceType = req.devicetype();
    initUserReq.areaID = (req.areaid() <= 0) ? 86 : req.areaid();
    initUserReq.isRobot = 0;
    initUserReq.reg_type = 0;//账号,暂未使用

    switch (req.platform())
    {
    case E_Platform_Type::E_PLATFORM_TYPE_IOS:
        initUserReq.platform = E_PLATFORM_TYPE_IOS;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_ANDROID:
        initUserReq.platform = E_PLATFORM_TYPE_ANDROID;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_H5:
        initUserReq.platform = E_PLATFORM_TYPE_H5;
        break;
    default:
        ROLLLOG_ERROR << "未知错误平台类型: " << req.platform() << endl;
        break;
    }

    //渠道ID
    switch (req.channnelid())
    {
    case E_Channel_ID::E_CHANNEL_ID_UNKNOWN:
        initUserReq.channnelID = E_CHANNEL_ID_UNKNOWN;
        break;
    case E_Channel_ID::E_CHANNEL_ID_TEST:
        initUserReq.channnelID = E_CHANNEL_ID_TEST;
        break;
    default:
        ROLLLOG_ERROR << "未知错误渠道类型: " << req.channnelid() << endl;
        break;
    }

    InitUserResp initUserResp;
    iRet = initUser(pDBAgentServant, initUserReq, initUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册日志
    vector<string> vLogRegister;
    vLogRegister.push_back(I2S(APP_ID));                   //AppId|DB_STR
    vLogRegister.push_back("1001");                        //GameId|DB_STR
    vLogRegister.push_back("0");                           //ChannelId|DB_STR
    vLogRegister.push_back(I2S(initUserReq.areaID));       //AreaId|DB_STR
    vLogRegister.push_back("0");                           //Platform|DB_STR
    vLogRegister.push_back(L2S(insertIDRsp.lastID));       //Uuid|DB_STR
    vLogRegister.push_back(initUserReq.userName);          //UserAccount|DB_STR
    vLogRegister.push_back(initUserReq.deviceID);          //DeviceId|DB_STR
    vLogRegister.push_back(initUserReq.deviceType);        //DeviceType|DB_STR
    vLogRegister.push_back(ip);                            //Ip|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(insertIDRsp.lastID, 20, vLogRegister);

    rsp.set_resultcode(0);
    rsp.set_uid(insertIDRsp.lastID);
    return XGameRetCode::SUCCESS;
}

//账号注册处理
int Processor::UserRegister2(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const map<std::string, std::string> &extraInfo)
{
    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username: " << req.username() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetRegisterInfoRsp getRegisterRsp;
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (getRegisterRsp.lUid > 0)
    {
        ROLLLOG_ERROR << "username exist, getRegisterRsp.lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetTableGUIDReq insertIDReq;
    insertIDReq.keyIndex = 0;
    insertIDReq.tableName = "tb_uid_guid";
    insertIDReq.fieldName = "uid";

    TGetTableGUIDRsp insertIDRsp;
    iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
    ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
    if (insertIDRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册帐号
    InitUserReq initUserReq;
    initUserReq.uid = insertIDRsp.lastID;
    initUserReq.userName = req.username();
    initUserReq.passwd = req.passwd();
    initUserReq.deviceID = req.deviceid();
    initUserReq.deviceType = req.devicetype();
    initUserReq.areaID = (req.areaid() <= 0) ? 86 : req.areaid();
    initUserReq.isRobot = 0;
    initUserReq.reg_type = 1;

    switch (req.platform())
    {
    case E_Platform_Type::E_PLATFORM_TYPE_IOS:
        initUserReq.platform = E_PLATFORM_TYPE_IOS;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_ANDROID:
        initUserReq.platform = E_PLATFORM_TYPE_ANDROID;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_H5:
        initUserReq.platform = E_PLATFORM_TYPE_H5;
        break;
    default:
        ROLLLOG_ERROR << "未知错误平台类型: " << req.platform() << endl;
        break;
    }

    switch (req.channnelid())
    {
    case E_Channel_ID::E_CHANNEL_ID_UNKNOWN:
        initUserReq.channnelID = E_CHANNEL_ID_UNKNOWN;
        break;
    case E_Channel_ID::E_CHANNEL_ID_TEST:
        initUserReq.channnelID = E_CHANNEL_ID_TEST;
        break;
    default:
        ROLLLOG_ERROR << "未知错误渠道类型: " << req.channnelid() << endl;
        break;
    }

    InitUserResp initUserResp;
    iRet = initUser(pDBAgentServant, initUserReq, initUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    //注册日志
    vector<string> vLogRegister;
    vLogRegister.push_back(I2S(APP_ID));              //AppId|DB_STR
    vLogRegister.push_back("1001");                   //GameId|DB_STR
    vLogRegister.push_back(I2S(req.channnelid()));    //ChannelId|DB_STR
    vLogRegister.push_back("0");                      //AreaId|DB_STR
    vLogRegister.push_back(I2S(req.platform()));      //Platform|DB_STR
    vLogRegister.push_back(L2S(insertIDRsp.lastID));  //Uuid|DB_STR
    vLogRegister.push_back(req.username());           //UserAccount|DB_STR
    vLogRegister.push_back(req.deviceid());           //DeviceId|DB_STR
    vLogRegister.push_back(req.devicetype());         //DeviceType|DB_STR
    vLogRegister.push_back(sRemoteIp);                //Ip|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(insertIDRsp.lastID, 20, vLogRegister);

    rsp.set_resultcode(0);
    rsp.set_uid(insertIDRsp.lastID);
    return 0;
}

//三方平台注册处理
int Processor::ThirdRegister(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, userinfo::UpdateUserInfoReq &userInfo, const int regType, const string &ip)
{
    if (req.username().length() < MIN_USERNAME_LEN || req.passwd().length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username: " << req.username() << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.username());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.username();
    getRegisterReq.iThirdParty = 1;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (getRegisterRsp.lUid > 0)
    {
        ROLLLOG_ERROR << "username exist, getRegisterRsp.lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取新uid
    TGetTableGUIDReq insertIDReq;
    insertIDReq.keyIndex = 0;
    insertIDReq.tableName = "tb_uid_guid";
    insertIDReq.fieldName = "uid";

    TGetTableGUIDRsp insertIDRsp;
    iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
    ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
    if (insertIDRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取facebook昵称为空时,设置初始昵称FB+UID
    if ((regType == 2) && userInfo.nickname.empty())
    {
        userInfo.nickname = "FB" + L2S(insertIDRsp.lastID);
        ROLLLOG_DEBUG << "httpGet load userInfo.nickname empty from thirdparty, now reset nickname:" << userInfo.nickname << endl;
    }

    //注册基本信息
    InitUserReq initUserReq;
    initUserReq.uid = insertIDRsp.lastID;
    initUserReq.userName = req.username();
    initUserReq.nickName = userInfo.nickname;
    initUserReq.headUrl = userInfo.head_url;
    initUserReq.gender = userInfo.gender;
    initUserReq.passwd = req.passwd();
    initUserReq.deviceID = req.deviceid();
    initUserReq.deviceType = req.devicetype();
    initUserReq.areaID = req.areaid();
    initUserReq.isRobot = 0;
    initUserReq.reg_type = regType;
    initUserReq.platform = (userinfo::E_Platform_Type)req.platform();
    initUserReq.channnelID = (userinfo::E_Channel_ID)req.channnelid();

    InitUserResp initUserResp;
    iRet = initUser(pDBAgentServant, initUserReq, initUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册日志
    vector<string> vLogRegister;
    vLogRegister.push_back(I2S(APP_ID));                   //AppId|DB_STR
    vLogRegister.push_back("1001");                        //GameId|DB_STR
    vLogRegister.push_back(I2S(req.channnelid()));         //ChannelId|DB_STR
    vLogRegister.push_back("0");                           //AreaId|DB_STR
    vLogRegister.push_back(I2S(req.platform()));           //Platform|DB_STR
    vLogRegister.push_back(L2S(insertIDRsp.lastID));       //Uuid|DB_STR
    vLogRegister.push_back(req.username());                //UserAccount|DB_STR
    vLogRegister.push_back(req.deviceid());                //DeviceId|DB_STR
    vLogRegister.push_back(req.devicetype());              //DeviceType|DB_STR
    vLogRegister.push_back(ip);                            //Ip|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(insertIDRsp.lastID, 20, vLogRegister);

    rsp.set_resultcode(0);
    rsp.set_uid(insertIDRsp.lastID);
    return 0;
}

//账号注册处理
int Processor::UserRegister(const login::RegisterReq req, login::RegisterResp &rsp, int areaID, string ip)
{
    if (req.userName.length() < MIN_USERNAME_LEN || req.passwd.length() < MIN_PASSWD_LEN)
    {
        ROLLLOG_ERROR << "parameter len too short, username len : " << req.userName << ", passwd len : " << req.passwd << ", ret: -1" << endl;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.userName);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.userName;

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (getRegisterRsp.lUid > 0)
    {
        ROLLLOG_ERROR << "username exist, getRegisterRsp.lUid: " << getRegisterRsp.lUid << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    TGetTableGUIDReq insertIDReq;
    insertIDReq.keyIndex = 0;
    insertIDReq.tableName = "tb_uid_guid";
    insertIDReq.fieldName = "uid";

    TGetTableGUIDRsp insertIDRsp;
    iRet = pDBAgentServant->getTableGUID(insertIDReq, insertIDRsp);
    ROLLLOG_DEBUG << "get last insert id, iRet: " << iRet << ", insertIDRsp: " << printTars(insertIDRsp) << endl;
    if (insertIDRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "fetch new user id err, iRet: " << iRet << ", iResult: " << insertIDRsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    InitUserReq initUserReq;
    initUserReq.uid = insertIDRsp.lastID;
    initUserReq.userName = req.userName;
    initUserReq.passwd = req.passwd;
    initUserReq.deviceID = req.deviceID;
    initUserReq.deviceType = req.deviceType;
    initUserReq.areaID = (req.areaID <= 0) ? 86 : req.areaID;
    initUserReq.isRobot = req.isRobot;
    initUserReq.reg_type = 0;//通过后台配置的机器人

    switch (req.platform)
    {
    case E_Platform_Type::E_PLATFORM_TYPE_IOS:
        initUserReq.platform = E_PLATFORM_TYPE_IOS;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_ANDROID:
        initUserReq.platform = E_PLATFORM_TYPE_ANDROID;
        break;
    case E_Platform_Type::E_PLATFORM_TYPE_H5:
        initUserReq.platform = E_PLATFORM_TYPE_H5;
        break;
    default:
        ROLLLOG_ERROR << "未知错误平台类型: " << req.platform << endl;
        break;
    }

    switch (req.channnelID)
    {
    case E_Channel_ID::E_CHANNEL_ID_UNKNOWN:
        initUserReq.channnelID = E_CHANNEL_ID_UNKNOWN;
        break;
    case E_Channel_ID::E_CHANNEL_ID_TEST:
        initUserReq.channnelID = E_CHANNEL_ID_TEST;
        break;
    default:
        ROLLLOG_ERROR << "未知错误渠道类型: " << req.channnelID << endl;
        break;
    }

    InitUserResp initUserResp;
    iRet = initUser(pDBAgentServant, initUserReq, initUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "init user info err, iRet: " << iRet << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //注册日志
    vector<string> vLogRegister;
    vLogRegister.push_back(I2S(APP_ID));             //AppId|DB_STR
    vLogRegister.push_back("1001");                  //GameId|DB_STR
    vLogRegister.push_back("0");                     //ChannelId|DB_STR
    vLogRegister.push_back(I2S(initUserReq.areaID)); //AreaId|DB_STR
    vLogRegister.push_back("0");                     //Platform|DB_STR
    vLogRegister.push_back(L2S(initUserReq.uid));    //Uuid|DB_STR
    vLogRegister.push_back(initUserReq.userName);    //UserAccount|DB_STR
    vLogRegister.push_back(initUserReq.deviceID);    //DeviceId|DB_STR
    vLogRegister.push_back(initUserReq.deviceType);  //DeviceType|DB_STR
    vLogRegister.push_back(ip);                      //Ip|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(initUserReq.uid, 20, vLogRegister);

    rsp.resultCode = 0;
    rsp.uid = insertIDRsp.lastID;
    return 0;
}

//手机号码登录
int Processor::PhoneLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo)
{
    if ((req.phone().length() < MIN_USERNAME_LEN)/* || (req.areaid() <= 0)*/)
    {
        ROLLLOG_ERROR << "invalid phone, phone: " << req.phone()/* << " or areaID: " << req.areaid()*/ << endl;
        rsp.set_resultcode(-1001);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.phone());
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        rsp.set_resultcode(-1);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    if (!checkPhoneNumber(req.phone()))
    {
        ROLLLOG_ERROR << "checkPhoneNumber() fail, phone=" << req.phone() << endl;
        rsp.set_resultcode(-1022);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    // string strGetAuthPhone = I2S(req.areaid()) + "-" + req.phone();//区号+手机号
    // auto &sc = g_app.getOuterFactoryPtr()->getSMSConfig();
    // if (sc.isOpen)
    // {
    //     std::string sCode;
    //     if (XGameRetCode::SUCCESS != getAuthData(strGetAuthPhone, sCode))
    //     {
    //         ROLLLOG_ERROR << "getAuthData() fail, strGetAuthPhone: " << strGetAuthPhone << endl;
    //         rsp.set_resultcode(-1032);
    //         return XGameRetCode::USER_INFO_PHONE_AUTH_CODE_ERROR;
    //     }

    //     if (S2I(sCode.c_str()) != req.msgcode())
    //     {
    //         ROLLLOG_ERROR << "Invalid verification code, reqCode=" << req.msgcode() << ", svrCode=" << sCode << endl;
    //         rsp.set_resultcode(-1033);
    //         return XGameRetCode::LOGIN_PARAM_ERROR;
    //     }
    // }

    //根据username查找uid
    TGetRegisterInfoReq getRegisterReq;
    getRegisterReq.keyIndex = 0;
    getRegisterReq.tableName = "tb_useraccount";
    getRegisterReq.userName = req.phone();

    TGetRegisterInfoRsp getRegisterRsp;
    int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
    ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
    if ((iRet != 0) || (getRegisterRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
        rsp.set_resultcode(-1003);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //获取用户标识
    tars::Int64 uid = getRegisterRsp.lUid;
    if (uid <= 0)
    {
        LoginProto::RegisterReq regReq;
        regReq.set_username(req.phone());
        regReq.set_passwd(req.phone());
        regReq.set_deviceid(req.deviceid());
        regReq.set_devicetype(req.devicetype());
        regReq.set_platform(req.platform());
        regReq.set_channnelid(req.channnelid());

        LoginProto::RegisterResp regRsp;
        iRet = UserRegister2(regReq, regRsp, extraInfo);
        if (iRet != 0 && regRsp.resultcode() != 0)
        {
            ROLLLOG_ERROR << "username not exist, iRet: " << iRet << ", resultcode: " << regRsp.resultcode() << endl;
            rsp.set_resultcode(-1014);
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        uid = regRsp.uid();
    }

    //uid不合法
    if (uid <= 0)
    {
        ROLLLOG_ERROR << "uid err, uid: " << uid << endl;
        rsp.set_resultcode(-1005);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //需要实现黑白名单功能
    UserAuthReq userAuthReq;
    userAuthReq.uid = uid;
    UserAuthResp userAuthResp;
    iRet = userAuth(pDBAgentServant, userAuthReq, userAuthResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user auth error, iRet: " << iRet << endl;
        rsp.set_resultcode(-1008);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (req.phone() != userAuthResp.password)
    {
        ROLLLOG_ERROR << "password error, iRet: " << iRet
                      << ", reqPass: " << req.phone()
                      << ", password: " << userAuthResp.password << endl;

        rsp.set_resultcode(-1009);
        return XGameRetCode::LOGIN_PASSWD_ERROR;
    }

    string strToken = generateUUIDStr();

    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(uid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
    wdataReq.clusterInfo.frageFactor = uid;

    vector<TField> fields;
    TField tField;
    tField.colArithType = E_NONE;
    tField.colName = "token";
    tField.colType = STRING;
    tField.colValue = strToken;
    fields.push_back(tField);
    tField.colName = "exptime";
    tField.colType = BIGINT;
    tField.colValue = L2S(time(NULL) + TOKEN_EXPTIME);
    fields.push_back(tField);
    wdataReq.fields = fields;

    TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    if (iRet != 0 || wdataRsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save token data err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        rsp.set_resultcode(-1010);
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    // if (sc.isOpen)
    // {
    //     //登录成功后,删除手机短信验证码
    //     if (XGameRetCode::SUCCESS != delAuthData(strGetAuthPhone))
    //     {
    //         ROLLLOG_ERROR << "delAuthData() fail, strGetAuthPhone: " << strGetAuthPhone << endl;
    //         rsp.set_resultcode(-1032);
    //         return XGameRetCode::LOGIN_PARAM_ERROR;
    //     }
    // }

    //login addr
    string sRemoteIp = "";
    auto iter = extraInfo.find("RemoteIp");
    if (iter != extraInfo.end())
        sRemoteIp = (*iter).second;

    //登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));           //AppId|DB_STR
    vLogLogin.push_back("1001");                //GameId|DB_STR
    vLogLogin.push_back(I2S(req.channnelid())); //ChannelId|DB_STR
    vLogLogin.push_back("0");                   //AreaId|DB_STR
    vLogLogin.push_back(I2S(req.platform()));   //Platform|DB_STR
    vLogLogin.push_back(L2S(uid));              //Uuid|DB_STR
    vLogLogin.push_back(req.deviceid());        //DeviceId|DB_STR
    vLogLogin.push_back(sRemoteIp);             //Ip|DB_STR
    vLogLogin.push_back("1");                   //OperationCode|DB_STR
    vLogLogin.push_back("0");                   //OnlineTime|DB_STR
    g_app.getOuterFactoryPtr()->asyncLog2DB(uid, 21, vLogLogin);

    //登录消息应答
    rsp.set_resultcode(0);
    rsp.set_uid(uid);
    rsp.set_token(strToken);
    ROLLLOG_DEBUG << "set token data, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    return 0;
}

//发送手机验证码
int Processor::PhoneMsgCode(const LoginProto::SendPhoneMessageCodeReq &req, LoginProto::SendPhoneMessageCodeResp &rsp)
{
    if (req.phone().length() < MIN_USERNAME_LEN)
    {
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    vector<string> details = split(req.phone(), "-");
    if ((int)details.size() != 2)
    {
        ROLLLOG_ERROR << "param error, req:" << logPb(req) << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    string strPhone = details[1];
    if (!checkPhoneNumber(strPhone))
    {
        ROLLLOG_ERROR << "checkPhoneNumber() fail, req:" << logPb(req) << endl;
        rsp.set_resultcode(XGameRetCode::LOGIN_PARAM_ERROR);
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto &sc = g_app.getOuterFactoryPtr()->getSMSConfig();
    if (sc.isOpen)
    {
        tars::Int32 iRandNum = ((rand() % 9 + 1) * 100000) + ((rand() % 9 + 1) * 10000) + ((rand() % 9 + 1) * 1000) + ((rand() % 9) * 100) + ((rand() % 9) * 10) + (rand() % 9);
        int iRet = sendAuthCode(req.phone(), iRandNum);
        if (XGameRetCode::SUCCESS != iRet)
        {
            ROLLLOG_ERROR << "Send verification code fail: phone=" << req.phone() << ", code= " << iRandNum << endl;
            rsp.set_resultcode(XGameRetCode::USER_INFO_PHONE_FORMAT_ERROR);
            return XGameRetCode::USER_INFO_PHONE_FORMAT_ERROR;
        }

        if (XGameRetCode::SUCCESS != setAuthData(req.phone(), iRandNum))
        {
            ROLLLOG_ERROR << "save verification code fail: phone=" << req.phone() << ", code= " << iRandNum << endl;
            rsp.set_resultcode(XGameRetCode::LOGIN_SERVER_ERROR);
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        ROLLLOG_DEBUG << "Send verification code succ: phone=" << req.phone() << ", code= " << iRandNum << endl;
    }

    rsp.set_resultcode(XGameRetCode::SUCCESS);
    return XGameRetCode::SUCCESS;
}

//绑定三方账号:暂时只支持绑定facebook账号
int Processor::BindThirdPartyAccount(const login::BindThirdPartyAccountReq &req, login::BindThirdPartyAccountResp &rsp)
{
    if ( (req.uid <= 0) || (req.openId.length() <= 0)
            || (req.accountType != login::E_LOGIN_TYPE_FACEBOOK)
            || (req.channnelID != login::E_CHANNEL_ID_FACEBOOK))
    {
        ROLLLOG_ERROR << "param invalid, login::BindThirdPartyAccountReq:" << printTars(req) << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.uid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null" << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pHallServant = g_app.getOuterFactoryPtr()->getHallServantPrx(req.uid);
    if (!pHallServant)
    {
        ROLLLOG_ERROR << "pHallServant is null" << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //检查用户是否已绑定过账号
    userinfo::GetUserResp getUserResp;
    int iRet = SelectUserAccount(req.uid, getUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "SelectUserAccount() fail, req.uid:" << req.uid << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if ((getUserResp.bindChannelId > 0) && (getUserResp.bindOpenId.length() > 0))
    {
        ROLLLOG_ERROR << "user account already be bind, can not bind again, getUserResp.bindChannelId:" << getUserResp.bindChannelId
                      << ",bindOpenId:" << getUserResp.bindOpenId << ", login::BindThirdPartyAccountReq:" << printTars(req) << endl;
        rsp.resultCode = -1;
        return XGameRetCode::USER_INFO_ACCOUNT_ALREADY_BIND;
    }

    std::string openid;
    if ((req.accountType == login::E_LOGIN_TYPE_FACEBOOK) && (req.channnelID == login::E_CHANNEL_ID_FACEBOOK))
    {
        //检查facebook账号是否已经存在
        openid = "FB_" + req.openId;
        TGetRegisterInfoReq getRegisterReq;
        getRegisterReq.keyIndex = 0;
        getRegisterReq.tableName = "tb_useraccount";
        getRegisterReq.userName = openid;
        getRegisterReq.iThirdParty = 1;

        TGetRegisterInfoRsp getRegisterRsp;
        int iRet = pDBAgentServant->getRegisterInfo(getRegisterReq, getRegisterRsp);
        ROLLLOG_DEBUG << "get user register info, iRet: " << iRet << ", getRegisterRsp: " << printTars(getRegisterRsp) << endl;
        if ((iRet != 0) || (getRegisterRsp.iResult != 0))
        {
            ROLLLOG_ERROR << "get user register info err, iRet: " << iRet << ", iResult: " << getRegisterRsp.iResult << endl;
            rsp.resultCode = -1;
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        if (getRegisterRsp.lUid > 0)
        {
            ROLLLOG_ERROR << "facebook openid already be used, can not use again, login::BindThirdPartyAccountReq:" << printTars(req)
                          << ", openid:" << openid << ", getRegisterRsp.lUid:" << getRegisterRsp.lUid << endl;
            rsp.resultCode = -1;
            return XGameRetCode::USER_INFO_FACEBOOK_ALREADY_USED;
        }
    }
    else
    {
        ROLLLOG_ERROR << "param invalid, login::BindThirdPartyAccountReq:" << printTars(req) << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_PARAM_ERROR;
    }

    //更新第三方绑定信息
    dataproxy::TWriteDataReq wdataReq;
    wdataReq.resetDefautlt();
    wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_ACCOUNT) + ":" + L2S(req.uid);
    wdataReq.operateType = E_REDIS_WRITE;
    wdataReq.paraExt.resetDefautlt();
    wdataReq.paraExt.queryType = dbagent::E_UPDATE;
    wdataReq.clusterInfo.resetDefautlt();
    wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
    wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    wdataReq.clusterInfo.frageFactor = tars::hash<string>()(L2S(req.uid));

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "bindChannelId";
    tfield.colType = dbagent::INT;
    tfield.colValue = I2S(req.channnelID);
    wdataReq.fields.push_back(tfield);
    tfield.colName = "bindOpenId";
    tfield.colType = dbagent::STRING;
    tfield.colValue = openid;
    wdataReq.fields.push_back(tfield);

    dataproxy::TWriteDataRsp wdataRsp;
    iRet = pDBAgentServant->redisWrite(wdataReq, wdataRsp);
    ROLLLOG_DEBUG << "set user account, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
    if ((iRet != 0) || (wdataRsp.iResult != 0))
    {
        ROLLLOG_ERROR << "set user account err, iRet: " << iRet << ", iResult: " << wdataRsp.iResult << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    //绑定奖励
    ModifyUserAccountReq modifyUserAccountReq;
    modifyUserAccountReq.uid = req.uid;
    modifyUserAccountReq.goldChange = g_app.getOuterFactoryPtr()->getUserInitWealth(2).bindgold;
    modifyUserAccountReq.changeType = XGameProto::GOLDFLOW::GOLDFLOW_ID_VISITOR_BANDFB;
    iRet = pHallServant->modifyUserAccount(modifyUserAccountReq);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "modifyUserAccount failed, modifyUserAccountReq: " << printTars(modifyUserAccountReq) << endl;
        rsp.resultCode = -1;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    rsp.resultCode = XGameRetCode::SUCCESS;
    return XGameRetCode::SUCCESS;
}

static bool queryRounterForConfigServer(config::ListRounterCfgResp &rsp)
{
    auto pConfigServant = g_app.getOuterFactoryPtr()->getConfigServantPrx();
    if (!pConfigServant)
    {
        ROLLLOG_ERROR << "load rounter info failed: pConfigServant is null" << endl;
        return false;
    }

    // //每分钟更新一次路由信息
    // static config::ListRounterCfgResp temp;
    // static std::atomic<int> lastUpdateTime(0);
    // if (TNOW - lastUpdateTime > 60)
    // {
    //     lastUpdateTime = TNOW;
    //     int iRet = pConfigServant->ListRounterCfg(temp);
    //     if (iRet != 0)
    //     {
    //         ROLLLOG_ERROR << "load rounter info failed, iRet: " << iRet << endl;
    //         return false;
    //     }

    //     rsp.iLastVersion = temp.iLastVersion;
    //     rsp.data = temp.data;
    // }

    int iRet = pConfigServant->ListRounterCfg(rsp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "load rounter info failed" << endl;
        return false;
    }

    return true;
}

//网关信息
int Processor::UserRounter(const LoginProto::UserRounterInfoReq &req, LoginProto::UserRounterInfoResp &rsp)
{
    config::ListRounterCfgResp resp;
    if (!queryRounterForConfigServer(resp))
    {
        ROLLLOG_ERROR << "load rounter info failed: pConfigServant is null" << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    if (resp.data.empty())
    {
        ROLLLOG_ERROR << "rounter list is empty" << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    std::vector<config::RounterCfg> availableNode;
    for (auto iter = resp.data.begin(); iter != resp.data.end(); iter++)
    {
        auto &node = iter->second;
        if (0 == node.state)
            continue;

        availableNode.push_back(node);
    }

    if (availableNode.empty())
    {
        ROLLLOG_ERROR << "availableNode is empty." << endl;
        rsp.set_routeraddr("");
        rsp.set_routerport(0);
        rsp.set_resultcode(XGameRetCode::INNER_ERROR);
        return XGameRetCode::INNER_ERROR;
    }

    int random = rand() % availableNode.size();
    auto &node = availableNode[random];
    rsp.set_routeraddr(node.addr);
    rsp.set_routerport(node.port);
    rsp.set_resultcode(XGameRetCode::SUCCESS);
    return XGameRetCode::SUCCESS;
}

//将验证写入缓存中
int Processor::setAuthData(const std::string &phone, const tars::Int32 &smsCode)
{
    if (phone.empty() || smsCode <= 0)
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << ", smscode: " << smsCode << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PHONE) + ":" + phone;
    req.operateType = E_REDIS_WRITE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    tfield.colValue = I2S(smsCode);
    req.fields.push_back(tfield);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "save smscode data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "set smscode data succ, iRet: " << iRet << ", wdataRsp: " << printTars(rsp) << ", code:" << smsCode << endl;
    return XGameRetCode::SUCCESS;
}

//从缓存中读取手机验证码
int Processor::getAuthData(const std::string &phone, std::string &ret)
{
    if (phone.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TReadDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PHONE) + ":" + phone;
    req.operateType = E_REDIS_READ;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    TField tfield;
    tfield.colArithType = E_NONE;
    tfield.colName = "token";
    tfield.colType = STRING;
    req.fields.push_back(tfield);

    TReadDataRsp rsp;
    int iRet = pDBAgentServant->redisRead(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "read data fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    bool bFind = false;
    for (auto it = rsp.fields.begin(); it != rsp.fields.end(); ++it)
    {
        for (auto itfields = it->begin(); itfields != it->end(); ++itfields)
        {
            if (itfields->colName == "token")
            {
                ret = itfields->colValue;
                bFind = true;
                break;
            }
        }
    }

    if (!bFind)
    {
        ROLLLOG_ERROR << "read sms-code fail, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_DEBUG << "read sms-code succ, iRet: " << iRet << ", sms-code: " << ret << endl;
    return XGameRetCode::SUCCESS;
}

//从缓存中删除手机验证码
int Processor::delAuthData(const std::string &phone)
{
    if (phone.empty())
    {
        ROLLLOG_ERROR << "invalid sms data err, phone: " << phone << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(phone);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null " << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    dataproxy::TWriteDataReq req;
    req.resetDefautlt();
    req.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_PHONE) + ":" + phone;
    req.operateType = E_REDIS_DELETE;
    req.clusterInfo.resetDefautlt();
    req.clusterInfo.busiType = E_REDIS_PROPERTY;
    req.clusterInfo.frageFactorType = E_FRAGE_FACTOR_STRING;
    req.clusterInfo.frageFactor = tars::hash<string>()(phone);

    dataproxy::TWriteDataRsp rsp;
    int iRet = pDBAgentServant->redisWrite(req, rsp);
    if (iRet != 0 || rsp.iResult != 0)
    {
        ROLLLOG_ERROR << "delete user auth data err, iRet: " << iRet << ", iResult: " << rsp.iResult << endl;
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    ROLLLOG_ERROR << "delete user auth data success, req.keyName: " << req.keyName << endl;

    return XGameRetCode::SUCCESS;
}

//产生uuid串
string Processor::generateUUIDStr()
{
    uuid_t uuid;
    uuid_generate(uuid);

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    uuid_unparse(uuid, buf);

    string strRet;
    strRet.assign(buf, strlen(buf));
    return strRet;
}

/********************************************************
Description:    实现HTTP/HTTPS GET请求
********************************************************/
size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    string data((const char *)ptr, (size_t)size * nmemb);
    *((stringstream *)stream) << data << endl;
    return size * nmemb;
}

/************************************
@ Brief:        GET请求
************************************/
int Processor::httpGet(const char *url, std::string &resJson)
{
    auto curl = curl_easy_init();
    if (!curl)
    {
        ROLLLOG_ERROR << "GET: curl is null" << endl;
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    std::stringstream out;
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // if (g_app.getOuterFactoryPtr()->getAgentOpenConfig())
    // {
    //     curl_easy_setopt(curl, CURLOPT_PROXY, "10.10.10.159:1081");
    // }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);

    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        ROLLLOG_ERROR << "curl_easy_perform failed: :" << curl_easy_strerror(res) << endl;
        curl_easy_cleanup(curl);
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    ROLLLOG_DEBUG << "url :" << url << endl;
    ROLLLOG_DEBUG << "rsp :" << out.str() << endl;

    resJson = out.str();
    curl_easy_cleanup(curl);
    return 0;
}

/************************************
@ Brief: POST请求
************************************/
int Processor::httpPost(const char *url, const std::string &postParams, std::string &resJson)
{
    auto curl = curl_easy_init();
    if (!curl)
    {
        ROLLLOG_ERROR << "POST: curl is null" << endl;
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    ROLLLOG_DEBUG << "post url :" << url << ", data: " << resJson << endl;

    curl_slist *header = nullptr;
    header = curl_slist_append(header, "content-type:application/json;charset=utf-8");

    std::stringstream out;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParams.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        ROLLLOG_ERROR << "curl_easy_perform failed: :" << curl_easy_strerror(res) << endl;
        curl_easy_cleanup(curl);
        return XGameRetCode::LOGIN_GETHTTP_ERROR;
    }

    resJson = out.str();
    ROLLLOG_DEBUG << "httpPost succ: url=" << url << ", postData=" << postParams << ", resJson=" << resJson << endl;
    curl_easy_cleanup(curl);
    return 0;
}

/**********************************************
{
     “ iss”：“ https://accounts.google.com”，
     “ sub”：“ 110169484474386276334”，
     “ azp”：“ 1008719970978-hb24n2dstb40o45d4feuo2ukqmcc6381.apps.googleusercontent.com”，
     “ aud”：“ 1008719970978-hb24n2dstb40o45d4feuo2ukqmcc6381.apps.googleusercontent.com”，
     “ iat”：“ 1433978353”，
     “ exp”：“ 1433981953”，
     “ email”：“ testuser@gmail.com”，
     “ email_verified”：“ true”，
     “ name”：“测试用户”，
     “ picture”：“ https://lh4.googleusercontent.com/-kYgzyAWpZzJ/ABCDEFGHI/AAAJKLMNOP/tIXL9Ir44LE/s99-c/photo.jpg”，
     “ given_name”：“测试”，
     “ family_name”：“用户”，
     “ locale”：“ en”
}
**********************************************/

int Processor::getUserInfoFromGoogle(const std::string &tokenid, const std::string &openid, userinfo::UpdateUserInfoReq &req)
{
    std::string url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + tokenid;
    std::string respData;
    int iRet = httpGet(url.c_str(), respData);
    if (0 != iRet || respData.empty())
    {
        ROLLLOG_ERROR << "load google data err iRet:" << iRet << endl;
        return iRet;
    }

    ROLLLOG_DEBUG << "google data:" << respData << endl;

    Json::Reader Reader;
    Json::Value DevJson;
    Reader.parse(respData, DevJson);
    if (!DevJson["error"].isNull())
    {
        ROLLLOG_ERROR << "get google data error. " << endl;
        return XGameRetCode::LOGIN_GETHTTP_DATA_ERROR;
    }

    std::vector<std::string> vAppId = g_app.getOuterFactoryPtr()->getGoogleConfig();

    if (DevJson["exp"].asString().empty() || DevJson["exp"].asString() < std::to_string(std::time(NULL)))
    {
        ROLLLOG_ERROR << "google token expires: " << DevJson["exp"].asString() << ", now:" << std::time(NULL) << endl;
        return XGameRetCode::LOGIN_TOKEN_EXPIRED;
    }

    if (DevJson["sub"].isString() && !DevJson["sub"].asString().empty())
    {
        if (DevJson["sub"].asString() != openid)
        {
            ROLLLOG_ERROR << "google sub error. openid: " << openid << ", sub:" << DevJson["sub"].asString() << endl;
            return XGameRetCode::LOGIN_GOOGLE_OPENID_ERROR;
        }
    }

    if (DevJson["aud"].isString() && !DevJson["aud"].asString().empty())
    {
        std::string aud = DevJson["aud"].asString();
        auto iter = std::find_if (vAppId.begin(), vAppId.end(), [aud](std::string & app_id) -> bool
        {
            return app_id == aud;
        });

        if (vAppId.end() == iter)
        {
            ROLLLOG_ERROR << "google aud error. aud: " << aud << endl;
            return XGameRetCode::LOGIN_GOOGLE_APPID_ERROR;
        }
    }

    req.head_url = DevJson["picture"].asString();
    req.nickname = DevJson["name"].asString();
    return iRet;
}

/********************************
{
    data: {
        app_id: YOUR_APP_ID,
        is_valid: true,
        metadata: {
            sso: "iphone-safari"
        },
        application: YOUR_APP_NAMESPACE,
        user_id: USER_ID,
        issued_at: 1366236791,
        expires_at: 1371420791,
        scopes: [ ]
    }
}
*********************************/
int Processor::checkFacebookAuth(const std::string &input_token)
{
    std::string accessToken = g_app.getOuterFactoryPtr()->getAccessFackbookToken();
    std::string authUrl = g_app.getOuterFactoryPtr()->getAuthFackbookUrl();
    std::string respData;
    std::string url = authUrl + "?access_token=" + accessToken + "&input_token=" + input_token;
    ROLLLOG_DEBUG << "check facebook token url :" << url << endl;
    int iRet = httpGet(url.c_str(), respData);
    if (0 != iRet || respData.empty())
    {
        ROLLLOG_ERROR << "check facebook err iRet:" << iRet << endl;
        return iRet;
    }

    ROLLLOG_DEBUG << "proc1" << endl;

    Json::Reader Reader;
    Json::Value DevJson;
    Reader.parse(respData, DevJson);
    if (DevJson["data"].isNull() || !DevJson["data"]["error"].isNull())
    {
        ROLLLOG_ERROR << "get facebook auth data error. " << endl;
        return XGameRetCode::LOGIN_FACEBOOK_AUTH_ERROR;
    }

    ROLLLOG_DEBUG << "proc2" << endl;

    if (DevJson["data"].isNull() || (DevJson["data"]["is_valid"].isBool() && DevJson["data"]["is_valid"].asBool() != true))
    {
        ROLLLOG_ERROR << "check facebook err. data exist:" << DevJson["data"].isObject() << ", is_valid:" << DevJson["data"]["is_valid"].asBool() << endl;
        return XGameRetCode::LOGIN_FACEBOOK_AUTH_ERROR;
    }

    ROLLLOG_DEBUG << "proc3" << endl;

    if (!DevJson["data"]["expires_at"].isNull() && DevJson["data"]["expires_at"].asUInt() < std::time(NULL))
    {
        ROLLLOG_ERROR << "check facebook expires:" << DevJson["data"]["expires_at"].asUInt() << ", now:" << std::time(NULL) << endl;
        return XGameRetCode::LOGIN_FACEBOOK_AUTH_ERROR;
    }

    ROLLLOG_DEBUG << "proc4" << endl;
    return 0;
}

/********************************
{
   "id": "107840414017910",
   "name": "\u5e2d\u6148\u6167",
   "first_name": "\u6148\u6167",
   "last_name": "\u5e2d",
   "picture":
    {
      "data":
        {
         "height": 50,
         "is_silhouette": true,
         "url": "https://XXXXX",
         "width": 50
        }
    }
}
********************************/
int Processor::getUserInfoFromFacebook(const std::string &tokenid, userinfo::UpdateUserInfoReq &req)
{
    int iRet = checkFacebookAuth(tokenid);
    if (0 != iRet)
    {
        ROLLLOG_ERROR << "checkFacebookAuth failed, iRet:" << iRet << endl;
        return iRet;
    }

    std::string getInfoUrl = g_app.getOuterFactoryPtr()->getFackbookInfoUrl();
    std::string url = getInfoUrl + "&access_token=" + tokenid;
    std::string respData;
    iRet = httpGet(url.c_str(), respData);
    if ((0 != iRet) || respData.empty())
    {
        ROLLLOG_ERROR << "httpGet load facebook data failed, iRet:" << iRet << ", url:" << url << endl;
        return iRet;
    }

    ROLLLOG_DEBUG << "httpGet load facebook data token url :" << url << endl;
    ROLLLOG_DEBUG << "httpGet load facebook data token rsp :" << respData << endl;

    ROLLLOG_DEBUG << "proc1" << endl;

    Json::Reader Reader;
    Json::Value DevJson;
    Reader.parse(respData, DevJson);
    if (!DevJson["error"].isNull())
    {
        ROLLLOG_ERROR << "httpGet load facebook data error." << endl;
        return XGameRetCode::LOGIN_FACEBOOK_DATA_ERROR;
    }

    ROLLLOG_DEBUG << "proc2" << endl;

    if ( !DevJson["name"].isNull() && DevJson["name"].isString() && !DevJson["name"].empty() )
    {
        req.nickname = DevJson["name"].asString();
    }

    ROLLLOG_DEBUG << "proc3" << endl;
    if ( !DevJson["gender"].isNull() && DevJson["gender"].isString() && !DevJson["gender"].empty() )
    {
        std::string strGender = DevJson["gender"].asString();
        if (strGender == "male")
        {
            req.gender = 1;
        }
        else
        {
            req.gender = 2;
        }
    }
    else
    {
        req.gender = rand() % 2 + 1;
    }

    ROLLLOG_DEBUG << "proc4" << endl;
    if ( !DevJson["picture"].isNull() && !DevJson["picture"]["data"].isNull() && !DevJson["picture"]["data"]["url"].isNull()
            && DevJson["picture"]["data"]["url"].isString() && !DevJson["picture"]["data"]["url"].empty() )
    {
        req.head_url = DevJson["picture"]["data"]["url"].asString();
    }
    else
    {
        int randHead = req.gender == 1 ? rand() % 5 + 1 : rand() % 5 + 6;
        req.head_url = "touxiang_" + I2S(randHead) + ".png";//随机设置头像 touxiang_(1-9).png
    }

    ROLLLOG_DEBUG << "proc5" << endl;
    return iRet;
}

/* 验证jwt数据，返回：
{
  u'c_hash': u'HpjAKvivbJr9j9ZxfFxA',
  u'aud': u'com.test.moe',
  u'iss': u'https://appleid.apple.com',
  u'email_verified': u'true',
  u'nonce_supported': True,
  u'exp': 1583829815,
  u'auth_time': 1583829215,
  u'iat': 1583829215,
  u'email': u'hua@163.com',
  u'sub': u'0017xx.9035989b3bxxxxx7c88b30086b37.xxx' # 用户唯一标志，相当于openid
}*/

bool Processor::ConvertJwkToPem(const std::string &strnn, const std::string &stree, std::string &strPubKey)
{
    auto nn = cppcodec::base64_url_unpadded::decode(strnn);
    auto ee = cppcodec::base64_url_unpadded::decode(stree);

    BIGNUM *modul = BN_bin2bn(nn.data(), nn.size(), NULL);
    BIGNUM *expon = BN_bin2bn(ee.data(), ee.size(), NULL);

    RSA *rr = RSA_new();
    EVP_PKEY *pRsaKey = EVP_PKEY_new();

    rr->n = modul;
    rr->e = expon;
    EVP_PKEY_assign_RSA(pRsaKey, rr);
    unsigned char *desc = new unsigned char[1024];
    memset(desc, 0, 1024);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rr);
    BIO_read(bio, desc, 1024);
    strPubKey = (char *)desc;
    BIO_free(bio);
    RSA_free(rr);
    if (strPubKey.empty())
    {
        return false;
    }
    return true;
}

int Processor::getUserInfoFromApple(const std::string &tokenid, userinfo::UpdateUserInfoReq &req)
{
    int iRet = 0;
    //string token = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLm1hc3Rlci53b25kZXJwb2tlci5uZXciLCJleHAiOjE1OTgzNTIwMTgsImlhdCI6MTU5ODM1MTQxOCwic3ViIjoiMDAyMDEyLmE2NmYyZDBjNDliYzQ2YzM4OTQ2YzI5NzczOGI1NjI0LjA3MzciLCJjX2hhc2giOiJ3VnBCbUxiMnI1NGNZTzlXQndwTTd3IiwiZW1haWwiOiJ3dV9qdW55YW5nQHFxLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImF1dGhfdGltZSI6MTU5ODM1MTQxOCwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlfQ.M6lo0MNcwZMDnZB9PtmN6snSr5EaMsJ_X4OYLb8CaPsYYSkes_z6fT-Wpf99Zxe16W4sAfmdfvn-OEDJuqMfL6i6ETOa1lqTH0eT3942GhtCMQpH8a-84hjOBQ-ysLhIvuEF22o92TU_gOSWGJ3Qc5MsS0ESR9EZ7iiSN-8AeQaz5pV-DmMCK5phvI-9MhA4qahz-ED2eYblkX-zASa7F0YIvLWWg8U0kf-8fookaCYo0qNMCjTo0e0bHXkiKe_I3_aOSlSvedyaMk36Xs2nW0Ocvg37HNo1OFiJldl5phtDXfl5zxYmeEu5Ma6rQpU1BSgOt5rrL6Sk2j4NkPUqKA";
    auto decoded = jwt::decode(tokenid);
    //Get all payload claims
    std::ostringstream os;
    for (auto &e1 : decoded.get_payload_claims())
    {
        os << e1.first << " = " << e1.second.to_json() << std::endl;

        if ( e1.first == "aud" &&  e1.second.as_string() != "com.master.ttpoker")
        {
            return -1;
        }

    }
    ROLLLOG_DEBUG << "payload : " << os.str() << endl;

    std::string kid;
    for (auto &e2 : decoded.get_header_claims())
    {
        if (e2.first == "kid")
        {
            kid = e2.second.as_string();
        }
    }

    //获取共钥
    std::string url = "https://appleid.apple.com/auth/keys";
    std::string respData;
    iRet = httpGet(url.c_str(), respData);
    if (0 != iRet || respData.empty())
    {
        ROLLLOG_ERROR << "load apple keys err. iRet:" << iRet << endl;
        return iRet;
    }

    Json::Reader Reader;
    Json::Value ReqKeyJson;
    Json::Value nn_an_ee;
    Reader.parse(respData, ReqKeyJson);
    for(auto key : ReqKeyJson["keys"])
    {
        if (key["kid"] == kid)
        {
            nn_an_ee = key;
        }
    }

    std::string strPubKey;
    bool bgetPublishKey = ConvertJwkToPem(nn_an_ee["n"].asString(), nn_an_ee["e"].asString(), strPubKey);
    if (!bgetPublishKey)
    {
        return -2;
    }
    //ROLLLOG_DEBUG << " strPubKey: "<< strPubKey <<endl;

    //共钥验证
    try
    {
        auto verifie = jwt::verify().allow_algorithm(jwt::algorithm::rs256(strPubKey, "", "", "")).with_issuer("https://appleid.apple.com");
        verifie.verify(decoded);

        /*        os.str("");
                for (auto &e : decoded.get_header_claims())
                    os << e.first << " = " << e.second.to_json() << std::endl;
                for (auto &e : decoded.get_payload_claims())
                    os << e.first << " = " << e.second.to_json() << std::endl;
                ROLLLOG_DEBUG<<"end:"<<os.str()<<endl;*/
    }
    catch (const std::exception &e)
    {
        ROLLLOG_DEBUG << "verify err. message: " << e.what() << endl;
        return -3;
    }

    return 0;
}

/**
 *  请求内容{"account":"N6000001",
 *    "password":"123456",
 *    "msg":"【253云通讯】您的验证码是2530",
 *    "phone":"15800000000",
 *    "sendtime":"201704101400",
 *    "report":"true",
 *    "extend":"555",
 *    "uid":"321abc"
 *  }
 * [Processor::sendAuthCode description]
 * @param  phone   [description]
 * @param  smsCode [description]
 * @return         [description]
 */
int Processor::sendAuthCode(const std::string &phone, const tars::Int32 &smsCode)
{
    if (phone.empty() || (smsCode <= 0))
    {
        ROLLLOG_ERROR << "param error, phone: " << phone << ", smsCode: " << smsCode << endl;
        return -1;
    }

    vector<string> details = split(phone, "-");
    if ((int)details.size() != 2)
    {
        ROLLLOG_ERROR << "param error, phone: " << phone << endl;
        return -1;
    }

    int iRet = XGameRetCode::SUCCESS;
    std::string respData;
    std::string time = CurTimeFormat();
    std::string str = I2S(smsCode);

    std::string strArea = details[0];
    std::string strPhone = details[1];
    std::string strAuthPhone = "";
    if (strArea == "86")
    {
        strAuthPhone = strPhone;//国内手机号无区号

        auto &sms = g_app.getOuterFactoryPtr()->getSMSConfig();
        std::string sMsg = replace(sms.content, "msg", str.c_str());

        char buffer[2048] = {'\0'};
        sprintf(buffer, "{\"account\":\"%s\",\"password\":\"%s\",\"msg\":\"%s\",\"phone\":\"%s\",\"sendtime\":\"%s\",\"report\":\"true\",\"extend\":\"1000\",\"uid\":\"\"}",
                sms.account.c_str(), sms.password.c_str(), sMsg.c_str(), strAuthPhone.c_str(), time.c_str());

        ROLLLOG_DEBUG << "post data: " << buffer << endl;

        iRet = httpPost(sms.sendURL.c_str(), buffer, respData);
        if ((XGameRetCode::SUCCESS != iRet) || respData.empty())
        {
            ROLLLOG_ERROR << "httpPost failed, iRet: " << iRet << ", respData:" << respData << endl;
            return iRet;
        }
    }
    else
    {
        strAuthPhone = strArea + strPhone;//海外手机号带区号

        std::string sMsg = "";
        auto &smsOversea = g_app.getOuterFactoryPtr()->getSMSConfigOversea();
        auto &smsIndia = g_app.getOuterFactoryPtr()->getSMSConfigIndia();
        if (strArea == "91")
        {
            sMsg = replace(smsIndia.content, "msg", str.c_str());
        }
        else
        {
            sMsg = replace(smsOversea.content, "msg", str.c_str());
        }

        char buffer[2048] = {'\0'};
        sprintf(buffer, "{\"account\":\"%s\",\"password\":\"%s\",\"msg\":\"%s\",\"mobile\":\"%s\"}",
                smsOversea.account.c_str(), smsOversea.password.c_str(), sMsg.c_str(), strAuthPhone.c_str());

        ROLLLOG_DEBUG << "Oversea post data: " << buffer << endl;

        iRet = httpPost(smsOversea.sendURL.c_str(), buffer, respData);
        if ((XGameRetCode::SUCCESS != iRet) || respData.empty())
        {
            ROLLLOG_ERROR << "httpPost failed, iRet: " << iRet << ", respData:" << respData << endl;
            return iRet;
        }
    }

    Json::Value retJson;
    Json::Reader reader;
    reader.parse(respData, retJson);

    std::string sCode = retJson["code"].asString();
    std::string sTime = retJson["time"].asString();
    std::string sMsgId = retJson["msgId"].asString();
    iRet = atoi(sCode.c_str());
    if (XGameRetCode::SUCCESS != iRet)
    {
        std::string sError = retJson["errorMsg"].asString();
        ROLLLOG_ERROR << "send phone code fail: iRet=" << iRet << ", sError=" <<  sError << ", sMsgId=" << sMsgId << ", sTime=" << sTime << endl;
        return iRet;
    }

    ROLLLOG_DEBUG << "send phone code succ: iRet=" << iRet << ", sMsgId=" << sMsgId << ", sTime=" << sTime << endl;
    return XGameRetCode::SUCCESS;
}

