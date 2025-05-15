#include "LoginServantImp.h"
#include "servant/Application.h"
#include "LogComm.h"
#include "globe.h"
#include "XGameComm.pb.h"
#include "XGameHttp.pb.h"
#include "CommonCode.pb.h"
#include "CommonStruct.pb.h"
#include "UserInfo.pb.h"
#include "login.pb.h"
#include "DataProxyProto.h"
#include "ServiceDefine.h"
#include "util/tc_hash_fun.h"
#include "LoginServer.h"
#include "Processor.h"
#include "LogDefine.h"
#include "Push.h"
#include "uuid.h"
#include <regex>

//
using namespace std;
using namespace JFGame;
using namespace login;
using namespace dataproxy;
using namespace userinfo;

//////////////////////////////////////////////////////
void LoginServantImp::initialize()
{
    //initialize servant here:
    //...
}

//////////////////////////////////////////////////////
void LoginServantImp::destroy()
{
    //destroy servant here:
    //...
}

//http请求处理接口
tars::Int32 LoginServantImp::doRequest(const vector<tars::Char> &reqBuf, const map<std::string, std::string> &extraInfo,
                                       vector<tars::Char> &rspBuf, tars::TarsCurrentPtr current)
{
    FUNC_ENTRY("");

    int iRet = 0;

    __TRY__

    if (reqBuf.empty())
    {
        iRet = -1;
        return iRet;
    }

    XGameHttp::THttpPackage thttpPack;

    __TRY__
    if (!reqBuf.empty())
    {
        pbToObj(reqBuf, thttpPack);
    }
    __CATCH__

    if (thttpPack.vecdata().empty())
    {
        iRet = -2;
        return iRet;
    }

    int64_t ms1 = TNOWMS;

    XGameHttp::THttpPackage thttpPackRsp;
    switch (thttpPack.nmsgid())
    {
    // 网关信息
    case XGameProto::ActionName::USER_ROUNTER:
    {
        LoginProto::UserRounterInfoReq rounterReq;
        LoginProto::UserRounterInfoResp routerResp;
        pbToObj(thttpPack.vecdata(), rounterReq);
        iRet = ProcessorSingleton::getInstance()->UserRounter(rounterReq, routerResp);
        routerResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(routerResp));
        break;
    }
    // 账号登录
    case XGameProto::ActionName::USER_LOGIN:
    {
        LoginProto::UserLoginReq userLoginReq;
        LoginProto::UserLoginResp userLoginResp;
        pbToObj(thttpPack.vecdata(), userLoginReq);
        iRet = ProcessorSingleton::getInstance()->UserLogin(userLoginReq, userLoginResp, extraInfo);
        userLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(userLoginResp));
        break;
    }
    // 账号注册
    case XGameProto::ActionName::USER_REGISTER:
    {
        LoginProto::RegisterReq registerReq;
        pbToObj(thttpPack.vecdata(), registerReq);
        LoginProto::RegisterResp registerResp;
        iRet = ProcessorSingleton::getInstance()->UserRegister2(registerReq, registerResp, extraInfo);
        registerResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(registerResp));
        break;
    }
    // 帐号登出
    case XGameProto::ActionName::LOGIN_LOGOUT:
    {
        LoginProto::LogoutReq logoutReq;
        pbToObj(thttpPack.vecdata(), logoutReq);
        LoginProto::LogoutResp logoutResp;
        iRet = ProcessorSingleton::getInstance()->UserLogout(logoutReq, logoutResp);
        logoutResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(logoutResp));
        break;
    }
    // 设备登录
    case XGameProto::ActionName::LOGIN_DEVICE:
    {
        LoginProto::DeviceLoginReq deviceLoginReq;
        pbToObj(thttpPack.vecdata(), deviceLoginReq);
        LoginProto::DeviceLoginResp deviceLoginResp;
        iRet = ProcessorSingleton::getInstance()->DeviceLogin(deviceLoginReq, deviceLoginResp, extraInfo);
        deviceLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(deviceLoginResp));
        break;
    }
    //第三方登录Google
    case XGameProto::ActionName::LOGIN_GOOGLE:
    case XGameProto::ActionName::LOGIN_FACEBOOK:
    case XGameProto::ActionName::LOGIN_APPLE:
    {
        LoginProto::ThirdPartyLoginReq thirdLoginReq;
        pbToObj(thttpPack.vecdata(), thirdLoginReq);
        LoginProto::ThirdPartyLoginResp thirdLoginResp;
        iRet = ProcessorSingleton::getInstance()->ThirdPartyLogin(thirdLoginReq, thirdLoginResp, extraInfo);
        thirdLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(thirdLoginResp));
        break;
    }
    //快速登录
    case XGameProto::ActionName::LOGIN_QUICK:
    {
        LoginProto::QuickLoginReq quickLoginReq;
        pbToObj(thttpPack.vecdata(), quickLoginReq);
        LoginProto::QuickLoginResp quickLoginResp;
        iRet = ProcessorSingleton::getInstance()->QuickLogin(quickLoginReq, quickLoginResp, extraInfo);
        quickLoginResp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(quickLoginResp));
        break;
    }
    // 手机登录
    case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT:
    {
        LoginProto::PhoneLoginReq phoneLoginReq;
        pbToObj(thttpPack.vecdata(), phoneLoginReq);
        LoginProto::PhoneLoginResp phoneLoginRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneLogin(phoneLoginReq, phoneLoginRsp, extraInfo);
        phoneLoginRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phoneLoginRsp));
        break;
    }
    // 手机验证码
    case XGameProto::ActionName::USER_SEND_PHONE_CODE:
    {
        LoginProto::SendPhoneMessageCodeReq phoneMsgCodeReq;
        pbToObj(thttpPack.vecdata(), phoneMsgCodeReq);
        LoginProto::SendPhoneMessageCodeResp phoneMsgCodeRsp;
        iRet = ProcessorSingleton::getInstance()->PhoneMsgCode(phoneMsgCodeReq, phoneMsgCodeRsp);
        phoneMsgCodeRsp.set_resultcode(iRet);
        thttpPackRsp.set_vecdata(pbToString(phoneMsgCodeRsp));
        break;
    }
    //异常
    default:
    {
        ROLLLOG_ERROR << "invalid msgid." << endl;
        iRet = -101;
        return iRet;
    }
    }

    int64_t ms2 = TNOWMS;
    if ((ms2 - ms1) > COST_MS)
    {
        ROLLLOG_WARN << "@Performance, msgid:" << thttpPack.nmsgid() << ", costTime:" << (ms2 - ms1) << endl;
    }

    ROLLLOG_DEBUG << "recv msg, msgid : " << thttpPack.nmsgid() << ", iRet: " << iRet << endl;

    auto ptuid = thttpPackRsp.mutable_stuid();
    ptuid->set_luid(thttpPack.stuid().luid());
    ptuid->set_stoken(thttpPack.stuid().stoken());

    thttpPackRsp.set_iver(thttpPack.iver());
    thttpPackRsp.set_iseq(thttpPack.iseq());
    thttpPackRsp.set_nmsgid(thttpPack.nmsgid());
    pbTobuffer(thttpPackRsp, rspBuf);

    ROLLLOG_DEBUG << "response buff size: " << rspBuf.size() << endl;

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//tcp请求处理接口
tars::Int32 LoginServantImp::onRequest(tars::Int64 lUin, const std::string &sMsgPack, const std::string &sCurServrantAddr, const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo,
                                       tars::TarsCurrentPtr current)
{
    int iRet = 0;

    __TRY__

    ROLLLOG_DEBUG << "recv msg, uid : " << lUin << ", addr : " << stClientParam.sAddr << endl;

    LoginServant::async_response_onRequest(current, 0);

    //解码
    XGameComm::TPackage pkg;
    pbToObj(sMsgPack, pkg);

    //无数据
    if (pkg.vecmsghead_size() == 0)
    {
        ROLLLOG_DEBUG << "package empty." << endl;
        return -1;
    }

    ROLLLOG_DEBUG << "recv msg, uid : " << lUin << ", msg : " << logPb(pkg) << endl;

    //消息分发处理
    for (int i = 0; i < pkg.vecmsghead_size(); ++i)
    {
        int64_t ms1 = TNOWMS;

        const XGameComm::TMsgHead &head = pkg.vecmsghead(i);
        switch (head.nmsgid())
        {
        // 账号登录
        case XGameProto::ActionName::USER_LOGIN:
        {
            LoginProto::UserLoginReq userLoginReq;
            pbToObj(pkg.vecmsgdata(i), userLoginReq);
            iRet = onUserLogin(pkg, userLoginReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 账号注册
        case XGameProto::ActionName::USER_REGISTER:
        {
            LoginProto::RegisterReq registerReq;
            pbToObj(pkg.vecmsgdata(i), registerReq);
            iRet = onUserRegister(pkg, registerReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 账号登出
        case XGameProto::ActionName::LOGIN_LOGOUT:
        {
            LoginProto::LogoutReq logoutReq;
            logoutReq.set_uid(pkg.stuid().luid());
            iRet = onUserLogout(pkg, logoutReq, sCurServrantAddr);
            break;
        }
        // 设备登录
        case XGameProto::ActionName::LOGIN_DEVICE:
        {
            LoginProto::DeviceLoginReq deviceLoginReq;
            pbToObj(pkg.vecmsgdata(i), deviceLoginReq);
            iRet = onDeviceLogin(pkg, deviceLoginReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 手机登录
        case XGameProto::ActionName::LOGIN_PHONE_ACCOUNT:
        {
            LoginProto::PhoneLoginReq phoneLoginReq;
            pbToObj(pkg.vecmsgdata(i), phoneLoginReq);
            iRet = onPhoneLogin(pkg, phoneLoginReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 手机验证码
        case XGameProto::ActionName::USER_SEND_PHONE_CODE:
        {
            LoginProto::SendPhoneMessageCodeReq msgCodeReq;
            pbToObj(pkg.vecmsgdata(i), msgCodeReq);
            iRet = onSendPhoneMsgCode(pkg, msgCodeReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 绑定三方账号
        case XGameProto::ActionName::USER_BIND_THIRDPARTY_ACCOUNT:
        {
            LoginProto::BindThirdPartyAccountReq bindThirdPartyAccountReq;
            pbToObj(pkg.vecmsgdata(i), bindThirdPartyAccountReq);
            iRet = onBindThirdPartyAccount(pkg, bindThirdPartyAccountReq, sCurServrantAddr);
            break;
        }
        // 在线用户零点更新
        case XGameProto::ActionName::USER_STATE_ZERO_ONLINE_UPDATE:
        {
            LoginProto::OnlineUserZeroUpdateReq onlineUserZeroUpdateReq;
            pbToObj(pkg.vecmsgdata(i), onlineUserZeroUpdateReq);
            iRet = onUpdateOnlineUserZeroInfo(pkg, onlineUserZeroUpdateReq, sCurServrantAddr, stClientParam, stUserBaseInfo);
            break;
        }
        // 用户行为上报统计
        case XGameProto::ActionName::USER_ACTION_REPORT_STATISTICS:
        {
            LoginProto::UserActionReportReq userActionReportReq;
            pbToObj(pkg.vecmsgdata(i), userActionReportReq);
            iRet = onUserActionReport(pkg, userActionReportReq, sCurServrantAddr);
            break;
        }
        //异常处理
        default:
        {
            ROLLLOG_ERROR << "invalid msg id, uid: " << lUin << ", msg id: " << head.nmsgid() << endl;
            break;
        }
        }

        int64_t ms2 = TNOWMS;
        if ((ms2 - ms1) > COST_MS)
        {
            ROLLLOG_WARN << "@Performance, msgid:" << head.nmsgid() << ", costTime:" << (ms2 - ms1) << endl;
        }

        ROLLLOG_DEBUG << "recv msg, msgid : " << head.nmsgid() << ", iRet: " << iRet << endl;
    }

    __CATCH__;
    return iRet;
}

//校验token
tars::Int32 LoginServantImp::checkLoginToken(const login::CheckLoginTokenReq &req, login::CheckLoginTokenResp &resp, tars::TarsCurrentPtr current)
{
    if (req.lUid < 0 || req.sToken.empty())
    {
        ROLLLOG_ERROR << "paramter err, uid: " << req.lUid << ", token: " << req.sToken << endl;
        resp.resultCode = XGameRetCode::ARG_NULL_ERROR;
        resp.sHallId = "";
        return XGameRetCode::ARG_NULL_ERROR;
    }

    auto pDBAgentServant = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(req.lUid);
    if (!pDBAgentServant)
    {
        ROLLLOG_ERROR << "pDBAgentServant is null, uid: " << req.lUid << ", token: " << req.sToken << endl;
        resp.resultCode = XGameRetCode::ARG_NULL_ERROR;
        resp.sHallId = "";
        return XGameRetCode::ARG_NULL_ERROR;
    }

    userinfo::GetUserResp getUserResp;
    int iRet = ProcessorSingleton::getInstance()->SelectUserAccount(req.lUid, getUserResp);
    if ((iRet != 0) && (iRet != -3))
    {
        ROLLLOG_ERROR << "SelectUserAccount() fail, req.lUid : " << req.lUid << endl;
        resp.resultCode = XGameRetCode::LOGIN_SERVER_ERROR;
        resp.sHallId = "";
        return XGameRetCode::LOGIN_SERVER_ERROR;
    }

    if (iRet == -3)
    {
        resp.resultCode = XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
        resp.sHallId = "";
        ROLLLOG_ERROR << "invalid lUid: " << req.lUid << endl;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    string sztoken = "";
    long exptime = 0;
    //查询token
    {
        dataproxy::TReadDataReq dataReq;
        dataReq.resetDefautlt();
        dataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(LOGIN_TOKEN) + ":" + L2S(req.lUid);
        dataReq.operateType = E_REDIS_READ;
        dataReq.clusterInfo.resetDefautlt();
        dataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        dataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        dataReq.clusterInfo.frageFactor = req.lUid;

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;
        tfield.colName = "token";
        tfield.colType = STRING;
        fields.push_back(tfield);
        tfield.colName = "exptime";
        tfield.colType = BIGINT;
        fields.push_back(tfield);
        dataReq.fields = fields;

        TReadDataRsp dataRsp;
        int iRet = pDBAgentServant->redisRead(dataReq, dataRsp);
        ROLLLOG_DEBUG << "get user token data, uid: " << req.lUid << ", iRet: " << iRet << ", dataRsp: " << printTars(dataRsp) << endl;
        if (iRet != 0 || dataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "get user token err, uid: " << req.lUid << ", iRet: " << iRet << ", iResult: " << dataRsp.iResult << endl;
            resp.resultCode = XGameRetCode::LOGIN_SERVER_ERROR;
            resp.sHallId = "";
            return XGameRetCode::LOGIN_SERVER_ERROR;
        }

        for (auto it = dataRsp.fields.begin(); it != dataRsp.fields.end(); ++it)
        {
            for (auto ituid = it->begin(); ituid != it->end(); ++ituid)
            {
                if (ituid->colName == "token")
                {
                    sztoken = ituid->colValue;
                }
                else if (ituid->colName == "exptime")
                {
                    exptime = S2L(ituid->colValue);
                }
            }
        }
    }

    //不合法
    if (req.sToken != sztoken)
    {
        resp.resultCode = XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
        resp.sHallId = "";
        ROLLLOG_DEBUG << "invalid token, uid: " << req.lUid << ", req token: " << req.sToken << ", fact token: " << sztoken << endl;
        return XGameRetCode::LOGIN_TOKEN_INCONSISTENT;
    }

    if (exptime < time(NULL))
    {
        resp.resultCode = XGameRetCode::LOGIN_TOKEN_EXPIRED;
        resp.sHallId = "";
        ROLLLOG_DEBUG << "expired token, uid: " << req.lUid << ",sToken: " << req.sToken << ", exptime: " << exptime << ", now :" << time(NULL) << endl;
        return XGameRetCode::LOGIN_TOKEN_EXPIRED;
    }

    //用户登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));
    vLogLogin.push_back("1001");
    vLogLogin.push_back("0");
    vLogLogin.push_back("0");
    vLogLogin.push_back("0");
    vLogLogin.push_back(L2S(req.lUid));
    vLogLogin.push_back("");
    vLogLogin.push_back(req.sRemoteIP);
    vLogLogin.push_back("3");
    vLogLogin.push_back("0");
    g_app.getOuterFactoryPtr()->asyncLog2DB(req.lUid, 21, vLogLogin);

    //合法
    resp.resultCode = XGameRetCode::SUCCESS;
    resp.sHallId = "";
    return XGameRetCode::SUCCESS;
}

//账号注册
tars::Int32 LoginServantImp::Register(const login::RegisterReq &req, login::RegisterResp &resp, tars::TarsCurrentPtr current)
{
    int iRet = 0;
    FUNC_ENTRY("");
    __TRY__

    if (req.userName.length() < 1 || req.passwd.length() < 4)
    {
        ROLLLOG_ERROR << "parameter length too short, username len: " << req.userName.length() << ", passwd len: " << req.passwd.length() << ", ret: -1" << endl;
        resp.resultCode = -1;
        return -1;
    }

    //根据IP查询域名标识
    // int areaID = 0;
    // LookupAreaID(current->getIp(), areaID);
    // ROLLLOG_DEBUG << "user arean info, areaID: " << areaID << endl;

    //账号注册
    iRet = ProcessorSingleton::getInstance()->UserRegister(req, resp, req.areaID, "");
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user register process err, userName: " << req.userName << ", iRet: " << iRet << endl;
    }
    else
    {
        if (req.isRobot != 0)
        {
            //机器人注册随机设置比赛基本数据
            gamerecord::ReportKOUserActInfoReq reportKOUserActInfoReq;
            reportKOUserActInfoReq.uid = resp.uid;
            reportKOUserActInfoReq.matchCount = 30 + std::rand() % 20;
            reportKOUserActInfoReq.winCount = std::rand() % 5;
            reportKOUserActInfoReq.rank = std::rand() % 50 + 1;
            g_app.getOuterFactoryPtr()->asyncReportKOUserActInfo(reportKOUserActInfoReq);

            srand((unsigned)time(NULL));

            gamerecord::ReportQSUserActInfoReq reportQSUserActInfoReq;
            reportQSUserActInfoReq.uid = resp.uid;
            reportQSUserActInfoReq.hdCardCount = 500 + std::rand() % 2500;
            reportQSUserActInfoReq.poolCount = 120 + std::rand() % 230;
            reportQSUserActInfoReq.winCount = 50 + std::rand() % 220;
            reportQSUserActInfoReq.showCount = 40 + std::rand() % 180;
            reportQSUserActInfoReq.cardType = 4 + std::rand() % 3;

            int cardFace = 0;
            int cardSuit = 0;
            std::map<int, int> mSuit =
            {
                {0, 0},
                {1, 16},
                {2, 32},
                {3, 48}
            };

            switch (reportQSUserActInfoReq.cardType) //屏蔽同花顺
            {
            case 4: //顺子
            {
                for (int j = 0; j < 100; j++)
                {
                    std::set<int> sSuit;
                    for (int i = 0; i < 5; i++)
                    {
                        if (cardFace <= 1 || cardSuit < 0)
                        {
                            cardFace = std::rand() % 9 + 2;
                            cardSuit = std::rand() % 4;
                        }
                        else
                        {
                            cardFace += 1;
                            cardSuit = std::rand() % 4;
                        }

                        sSuit.insert(cardSuit);
                        tars::Char card = (cardFace + mSuit[cardSuit]) & 0X00FF;
                        reportQSUserActInfoReq.cards.push_back(card);
                    }

                    if (mSuit.size() == 1)
                    {
                        reportQSUserActInfoReq.cards.clear();
                    }
                    else
                    {
                        break;
                    }
                }
            }
            break;
            case 5: //同花
            {
                for (unsigned int j = 0; j < 100; j++)
                {
                    int count = 0;
                    cardSuit = std::rand() % 4;
                    std::set<int> sCard;
                    while (true)
                    {
                        sCard.insert(std::rand() % 13 + 2);
                        if (sCard.size() >= 5 || count > 100)
                            break;

                        count++;
                    }

                    for (auto face : sCard)
                    {
                        tars::Char card = (face + mSuit[cardSuit]) & 0X00FF;
                        reportQSUserActInfoReq.cards.push_back(card);
                    }

                    if (sCard.size() == 5 && std::abs(*sCard.end() - *sCard.begin()) == 4)
                    {
                        reportQSUserActInfoReq.cards.clear();
                    }
                    else
                    {
                        break;
                    }
                }
            }
            break;
            case 6: //葫芦
            {
                int count = 0;
                int cardFace3 = std::rand() % 13 + 2;
                int cardFace2 = cardFace3 > 13 ? cardFace3 - 1 : cardFace3 + 1;
                while (true)
                {
                    cardFace2 = std::rand() % 13 + 2;
                    if (cardFace2 != cardFace3 || count > 100)
                        break;

                    count++;
                }

                for (int i = 0; i < 3; i++)
                {
                    tars::Char card = (cardFace3 + mSuit[i]) & 0X00FF;
                    reportQSUserActInfoReq.cards.push_back(card);
                }

                for (int j = 0; j < 2; j++)
                {
                    tars::Char card = (cardFace2 + mSuit[j]) & 0X00FF;
                    reportQSUserActInfoReq.cards.push_back(card);
                }
            }
            break;
            default:
            {
                //...
            }
            break;
            }

            //上报
            g_app.getOuterFactoryPtr()->asyncReportQSUserActInfo(reportQSUserActInfoReq);
        }
    }

    resp.resultCode = iRet;
    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//账号退出
tars::Int32 LoginServantImp::Logout(const login::UserLogoutReq &req, login::UserLogoutResp &resp, tars::TarsCurrentPtr current)
{
    int iRet = 0;
    FUNC_ENTRY("");
    __TRY__

    resp.resultCode = iRet;
    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//用户状态变化
tars::Int32 LoginServantImp::UserState(const long uid, const int state, tars::TarsCurrentPtr current)
{
    ROLLLOG_DEBUG << "user state change, uid: " << uid << ", state: " << state << endl;
    //更新用户下线时间
    updateUserLoginTime(uid, 2);
    return 0;
}

#define MIN_USERNAME_LEN 1           //用户名长度
#define MIN_PASSWD_LEN 4             //密码长度
#define MAX_UID_NUMBER_PER_ACCOUNT 1 //每个账号对应一个uid

//账号登录处理
int LoginServantImp::onUserLogin(const XGameComm::TPackage &pkg, const LoginProto::UserLoginReq &userLoginReq, const std::string &sCurServrantAddr, const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    map<std::string, std::string> extraInfo;
    extraInfo["RemoteIp"] = stClientParam.sAddr;

    LoginProto::UserLoginResp userLoginResp;
    iRet = ProcessorSingleton::getInstance()->UserLogin(userLoginReq, userLoginResp, extraInfo);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "logout err, userName: " << userLoginReq.username() << ", iRet: " << iRet << endl;
    }

    userLoginResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_LOGIN, userLoginResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//登出
int LoginServantImp::onUserLogout(const XGameComm::TPackage &pkg, const LoginProto::LogoutReq &logoutReq, const std::string &sCurServrantAddr)
{
    FUNC_ENTRY("");
    int iRet = 0;

    __TRY__

    LoginProto::LogoutResp logoutResp;
    iRet = ProcessorSingleton::getInstance()->UserLogout(logoutReq, logoutResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "logout err, uid: " << logoutReq.uid() << ", iRet: " << iRet << endl;
    }

    logoutResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::LOGIN_LOGOUT, logoutResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//设备号登录，即游客登录
int LoginServantImp::onDeviceLogin(const XGameComm::TPackage &pkg, const LoginProto::DeviceLoginReq &deviceLoginReq, const std::string &sCurServrantAddr,
                                   const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");

    int iRet = 0;

    __TRY__

    map<std::string, std::string> extraInfo;
    extraInfo["RemoteIp"] = stClientParam.sAddr;

    LoginProto::DeviceLoginResp deviceLoginResp;
    iRet = ProcessorSingleton::getInstance()->DeviceLogin(deviceLoginReq, deviceLoginResp, extraInfo);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "device login err, deviceNo: " << deviceLoginReq.deviceno() << ", iRet: " << iRet << endl;
    }

    deviceLoginResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::LOGIN_DEVICE, deviceLoginResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//账号注册处理
int LoginServantImp::onUserRegister(const XGameComm::TPackage pkg, const LoginProto::RegisterReq registerReq, const std::string &sCurServrantAddr, const JFGame::TClientParam &stClientParam,
                                    const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    //账号注册
    LoginProto::RegisterResp registerResp;
    iRet = ProcessorSingleton::getInstance()->UserRegister(registerReq, registerResp, stClientParam.sAddr);
    ROLLLOG_DEBUG << "onUserRegister, req: " << logPb(registerReq) << ", rsp: " << logPb(registerResp) << ", iRet: " << iRet << endl;
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user register process err, userName: " << registerReq.username() << ", iRet: " << iRet << endl;
    }

    registerResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_REGISTER, registerResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//手机账号登录
tars::Int32 LoginServantImp::onPhoneLogin(const XGameComm::TPackage pkg, const LoginProto::PhoneLoginReq &req, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");
    int iRet = 0;

    __TRY__

    map<string, string> extraInfo;
    extraInfo["RemoteIp"] = stClientParam.sAddr;

    LoginProto::PhoneLoginResp rsp;
    iRet = ProcessorSingleton::getInstance()->PhoneLogin(req, rsp, extraInfo);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "user register process err, phone: " << req.phone() << ", iRet: " << iRet << endl;
    }

    rsp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::LOGIN_PHONE_ACCOUNT, rsp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//发送手机验证码
tars::Int32 LoginServantImp::onSendPhoneMsgCode(const XGameComm::TPackage pkg, const LoginProto::SendPhoneMessageCodeReq &req, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");

    LoginProto::SendPhoneMessageCodeResp rsp;
    int iRet = ProcessorSingleton::getInstance()->PhoneMsgCode(req, rsp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "send phone code err, phone: " << req.phone() << ", iRet: " << iRet << endl;
    }

    rsp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_SEND_PHONE_CODE, rsp);
    FUNC_EXIT("", iRet);
    return iRet;
}

//绑定三方账号
int LoginServantImp::onBindThirdPartyAccount(const XGameComm::TPackage &pkg, const LoginProto::BindThirdPartyAccountReq &bindThirdPartyAccountReq, const std::string &sCurServrantAddr)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    login::BindThirdPartyAccountReq req;
    req.uid = pkg.stuid().luid();
    req.accountType = (login::E_Login_Type)bindThirdPartyAccountReq.accounttype();
    req.channnelID = (login::E_Channel_ID)bindThirdPartyAccountReq.channnelid();
    req.openId = bindThirdPartyAccountReq.openid();

    login::BindThirdPartyAccountResp resp;
    int iRet = ProcessorSingleton::getInstance()->BindThirdPartyAccount(req, resp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "BindThirdPartyAccount failed, iRet: " << iRet << ", LoginProto::BindThirdPartyAccountReq: " << logPb(bindThirdPartyAccountReq) << endl;
    }

    LoginProto::BindThirdPartyAccountResp bindThirdPartyAccountResp;
    bindThirdPartyAccountResp.set_resultcode(iRet);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_BIND_THIRDPARTY_ACCOUNT, bindThirdPartyAccountResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//在线用户零点更新
int LoginServantImp::onUpdateOnlineUserZeroInfo(const XGameComm::TPackage &pkg, const LoginProto::OnlineUserZeroUpdateReq &onlineUserZeroUpdateReq, const std::string &sCurServrantAddr,
        const JFGame::TClientParam &stClientParam, const JFGame::UserBaseInfoExt &stUserBaseInfo)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    LoginProto::OnlineUserZeroUpdateResp onlineUserZeroUpdateResp;
    if (onlineUserZeroUpdateReq.uid() <= 0)
    {
        ROLLLOG_ERROR << "param error, LoginProto::OnlineUserZeroUpdateReq: " << logPb(onlineUserZeroUpdateReq) << endl;
        onlineUserZeroUpdateResp.set_resultcode(XGameRetCode::ARG_INVALIDATE_ERROR);
        toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_STATE_ZERO_ONLINE_UPDATE, onlineUserZeroUpdateResp);
        return -1;
    }

    userinfo::GetUserResp getUserResp;
    int iRet = ProcessorSingleton::getInstance()->SelectUserAccount(onlineUserZeroUpdateReq.uid(), getUserResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "SelectUserAccount() fail, onlineUserZeroUpdateReq.uid():" << onlineUserZeroUpdateReq.uid() << endl;
        onlineUserZeroUpdateResp.set_resultcode(XGameRetCode::SYS_BUSY);
        toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_STATE_ZERO_ONLINE_UPDATE, onlineUserZeroUpdateResp);
        return -1;
    }

    string sRemoteIP = stClientParam.sAddr;

    //更新用户登出(或离线)时间/登录(或上线)时间
    updateUserLoginTime(onlineUserZeroUpdateReq.uid(), 2);

    //用户登出日志
    vector<string> vLogLogout;
    vLogLogout.push_back(I2S(APP_ID));
    vLogLogout.push_back("1001");
    vLogLogout.push_back(I2S((int)getUserResp.channnelID));
    vLogLogout.push_back(I2S(getUserResp.areaID));
    vLogLogout.push_back(I2S((int)getUserResp.platform));
    vLogLogout.push_back(L2S(onlineUserZeroUpdateReq.uid()));
    vLogLogout.push_back(getUserResp.deviceID);
    vLogLogout.push_back(sRemoteIP);
    vLogLogout.push_back("2");
    vLogLogout.push_back("0");//此处未统计实际在线时长,记录登出日志,主要用于后台统计用户留存
    g_app.getOuterFactoryPtr()->asyncLog2DB(onlineUserZeroUpdateReq.uid(), 21, vLogLogout);

    //用户登录日志
    vector<string> vLogLogin;
    vLogLogin.push_back(I2S(APP_ID));
    vLogLogin.push_back("1001");
    vLogLogin.push_back(I2S((int)getUserResp.channnelID));
    vLogLogin.push_back(I2S(getUserResp.areaID));
    vLogLogin.push_back(I2S((int)getUserResp.platform));
    vLogLogin.push_back(L2S(onlineUserZeroUpdateReq.uid()));
    vLogLogin.push_back(getUserResp.deviceID);
    vLogLogin.push_back(sRemoteIP);
    vLogLogin.push_back("1");
    vLogLogin.push_back("0");
    g_app.getOuterFactoryPtr()->asyncLog2DB(onlineUserZeroUpdateReq.uid(), 21, vLogLogin);

    onlineUserZeroUpdateResp.set_resultcode(XGameRetCode::SUCCESS);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_STATE_ZERO_ONLINE_UPDATE, onlineUserZeroUpdateResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

//用户行为上报统计
int LoginServantImp::onUserActionReport(const XGameComm::TPackage &pkg, const LoginProto::UserActionReportReq &userActionReportReq, const std::string &sCurServrantAddr)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    vector<string> veclog;
    veclog.push_back(I2S(APP_ID));
    veclog.push_back("1001");
    veclog.push_back(userActionReportReq.device());
    veclog.push_back(I2S(userActionReportReq.eventtype()));
    veclog.push_back(I2S(userActionReportReq.subtype()));
    veclog.push_back(L2S(userActionReportReq.uid()));
    g_app.getOuterFactoryPtr()->asyncLog2DB(userActionReportReq.uid(), 27, veclog);

    LoginProto::UserActionReportResp userActionReportResp;
    userActionReportResp.set_resultcode(XGameRetCode::SUCCESS);
    toClientPb(pkg, sCurServrantAddr, XGameProto::ActionName::USER_ACTION_REPORT_STATISTICS, userActionReportResp);

    __CATCH__;
    FUNC_EXIT("", iRet);
    return iRet;
}

int LoginServantImp::updateUserLoginTime(tars::Int64 uid, int iState)
{
    FUNC_ENTRY("");
    int iRet = 0;
    __TRY__

    if ((uid <= 0) || ((iState != 0) && (iState != 1) && (iState != 2)))
    {
        ROLLLOG_ERROR << "parameter error, uid: " << uid << ", iState: " << iState << endl;
        return -1;
    }

    userinfo::GetUserBasicResp getUserBasicResp;
    iRet = ProcessorSingleton::getInstance()->SelectUserInfo(uid, getUserBasicResp);
    if (iRet != 0)
    {
        ROLLLOG_ERROR << "SelectUserInfo() fail, uid: " << uid << endl;
        return -1;
    }

    bool needUpdate = false;
    int iNowTime = TNOW;
    if ((iState == 2) || ((iState == 1) && (getUserBasicResp.lastLoginTime != iNowTime)) || ((iState == 0) && (getUserBasicResp.lastLogoutTime != iNowTime)))
    {
        needUpdate = true;
    }

    if (needUpdate)
    {
        dataproxy::TWriteDataReq wdataReq;
        wdataReq.resetDefautlt();
        wdataReq.keyName = I2S(E_REDIS_TYPE_HASH) + ":" + I2S(USER_INFO) + ":" + L2S(uid);
        wdataReq.operateType = E_REDIS_WRITE;
        wdataReq.paraExt.resetDefautlt();
        wdataReq.paraExt.queryType = dbagent::E_UPDATE;
        wdataReq.clusterInfo.resetDefautlt();
        wdataReq.clusterInfo.busiType = E_REDIS_PROPERTY;
        wdataReq.clusterInfo.frageFactorType = E_FRAGE_FACTOR_USER_ID;
        wdataReq.clusterInfo.frageFactor = uid;

        vector<TField> fields;
        TField tfield;
        tfield.colArithType = E_NONE;

        if (iState == 2)//零点重置
        {
            //登录(或上线)
            tfield.colName = "last_login_time";
            tfield.colType = dbagent::STRING;
            tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(iNowTime);
            fields.push_back(tfield);
            //登出(或离线)
            tfield.colName = "last_logout_time";
            tfield.colType = dbagent::STRING;
            tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(iNowTime);
            fields.push_back(tfield);
        }
        else if (iState == 1) //上线状态
        {
            //登录(或上线)
            tfield.colName = "last_login_time";
            tfield.colType = dbagent::STRING;
            tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(iNowTime);
            fields.push_back(tfield);
        }
        else //下线状态
        {
            //登出(或离线)
            tfield.colName = "last_logout_time";
            tfield.colType = dbagent::STRING;
            tfield.colValue = g_app.getOuterFactoryPtr()->GetCustomTimeFormat(iNowTime);
            fields.push_back(tfield);
        }

        wdataReq.fields = fields;

        TWriteDataRsp wdataRsp;
        int iRet = g_app.getOuterFactoryPtr()->getDBAgentServantPrx(uid)->redisWrite(wdataReq, wdataRsp);
        if (iRet != 0 || wdataRsp.iResult != 0)
        {
            ROLLLOG_ERROR << "update user login time failed, iRet: " << iRet << ", wdataRsp: " << printTars(wdataRsp) << endl;
            return -1;
        }

        ROLLLOG_DEBUG << "111111111111111111111 update user login time success, uid: " << uid << ", iState: " << iState << endl;
    }

    __CATCH__
    FUNC_EXIT("", iRet);
    return iRet;
}

//发送消息到客户端
template <typename T>
int LoginServantImp::toClientPb(const XGameComm::TPackage &tPackage, const std::string &sCurServrantAddr, XGameProto::ActionName actionName, const T &t)
{
    XGameComm::TPackage rsp;
    rsp.set_iversion(tPackage.iversion());
    rsp.mutable_stuid()->set_luid(tPackage.stuid().luid());
    rsp.set_igameid(tPackage.igameid());
    rsp.set_sroomid(tPackage.sroomid());
    rsp.set_iroomserverid(tPackage.iroomserverid());
    rsp.set_isequence(tPackage.isequence());
    rsp.set_iflag(tPackage.iflag());

    auto mh = rsp.add_vecmsghead();
    mh->set_nmsgid(actionName);
    mh->set_nmsgtype(XGameComm::MSGTYPE::MSGTYPE_RESPONSE);
    mh->set_servicetype(XGameComm::SERVICE_TYPE::SERVICE_TYPE_LOGIN);
    rsp.add_vecmsgdata(pbToString(t));

    auto pPushPrx = Application::getCommunicator()->stringToProxy<JFGame::PushPrx>(sCurServrantAddr);
    if (pPushPrx)
    {
        ROLLLOG_DEBUG << "toClientPb, uid: " << tPackage.stuid().luid() << ", actionName: " << actionName << ", toclient pb: " << logPb(rsp) << ", t: " << logPb(t) << endl;
        pPushPrx->tars_hash(tPackage.stuid().luid())->async_doPushBuf(NULL, tPackage.stuid().luid(), pbToString(rsp));
    }
    else
    {
        ROLLLOG_ERROR << "pPushPrx is null, uid: " << tPackage.stuid().luid() << ", actionName: " << actionName << ", toclient pb: " << logPb(rsp) << ", t: " << logPb(t) << endl;
    }

    return 0;
}

//产生uuid串
string LoginServantImp::generateUUIDStr()
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
