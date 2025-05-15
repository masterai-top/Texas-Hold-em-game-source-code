#ifndef _Processor_H_
#define _Processor_H_

#include <util/tc_singleton.h>
#include "login.pb.h"
#include "LoginProto.h"
#include <curl/curl.h>
#include <json/json.h>
#include "UserInfoProto.h"
#include "CommonStruct.pb.h"
//
using namespace tars;

/**
 *请求处理类
 *
 */
class Processor
{
public:
    Processor();
    ~Processor();

public:
    //查询
    int SelectUserAccount(long uid, userinfo::GetUserResp &rsp);
    //查询
    int SelectUserInfo(long uid, userinfo::GetUserBasicResp &rsp);
    //更新用户第三方信息
    int UpdateUserThirdInfo(const userinfo::UpdateUserInfoReq &req, userinfo::UpdateUserInfoResp &rsp);
    //账号登录
    int UserLogin(const LoginProto::UserLoginReq &req, LoginProto::UserLoginResp &rsp, const map<string, string> &extraInfo);
    //登出
    int UserLogout(const LoginProto::LogoutReq &req, LoginProto::LogoutResp &rsp, bool sysOp = false, string ip = "");
    //游客登录
    int DeviceLogin(const LoginProto::DeviceLoginReq &req, LoginProto::DeviceLoginResp &rsp, const map<string, string> &extraInfo);
    //快速登录
    int QuickLogin(const LoginProto::QuickLoginReq &req, LoginProto::QuickLoginResp &rsp, const map<string, string> &extraInfo);
    //第三方登录
    int ThirdPartyLogin(const LoginProto::ThirdPartyLoginReq &req, LoginProto::ThirdPartyLoginResp &rsp, const map<string, string> &extraInfo);
    //账号注册处理
    int UserRegister(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const string &ip);
    //账号注册处理
    int UserRegister2(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, const map<std::string, std::string> &extraInfo);
    //账号注册处理
    int ThirdRegister(const LoginProto::RegisterReq req, LoginProto::RegisterResp &rsp, userinfo::UpdateUserInfoReq &userInfo, const int regType, const string &ip);
    //账号注册处理
    int UserRegister(const login::RegisterReq req, login::RegisterResp &rsp, int areaID, string ip);
    //手机号码登录
    int PhoneLogin(const LoginProto::PhoneLoginReq &req, LoginProto::PhoneLoginResp &rsp, const map<string, string> &extraInfo);
    //发送手机验证码
    int PhoneMsgCode(const LoginProto::SendPhoneMessageCodeReq &req, LoginProto::SendPhoneMessageCodeResp &rsp);
    //发送网关信息
    int UserRounter(const LoginProto::UserRounterInfoReq &req, LoginProto::UserRounterInfoResp &rsp);
    //绑定三方账号
    int BindThirdPartyAccount(const login::BindThirdPartyAccountReq &req, login::BindThirdPartyAccountResp &rsp);

private:
    //产生uuid串
    string generateUUIDStr();
    //
    int httpGet(const char *url, std::string &resJson);
    //
    int httpPost(const char *url, const std::string &postParams, std::string &resJson);
    //
    int getUserInfoFromGoogle(const std::string &tokenid, const std::string &openid, userinfo::UpdateUserInfoReq &req);
    //
    int getUserInfoFromApple(const std::string &tokenid, userinfo::UpdateUserInfoReq &req);
    //
    int getUserInfoFromFacebook(const std::string &tokenid, userinfo::UpdateUserInfoReq &req);
    //
    int checkFacebookAuth(const std::string &input_token);
    //
    int sendAuthCode(const std::string &phone, const tars::Int32 &smsCode);
    //
    int setAuthData(const std::string &phone, const tars::Int32 &smsCode);
    //
    int getAuthData(const std::string &phone, std::string &ret);
    //
    int delAuthData(const std::string &phone);

public:
    //
    bool ConvertJwkToPem(const std::string &strnn, const std::string &stree, std::string &strPubKey);
};

//singleton
typedef TC_Singleton<Processor, CreateStatic, DefaultLifetime> ProcessorSingleton;

#endif
