//
// Created by xmh on 18-7-18.
//

#ifndef CPP_SMS_ALIYUN_SMS_HPP
#define CPP_SMS_ALIYUN_SMS_HPP
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <openssl/hmac.h>
#include <string>
#include <ctime>
class aliyun_sms
{
public:
    aliyun_sms(const std::string& PhoneNumbers,const std::string & SignName,const std::string& TemplateCode = "SMS_121085196",const std::string& TemplateParam= "{\"code\":\"362387\"}")
    {
        char AccessKeyId[33] = "XXXXXXXXXXXXX";//阿里短信秘钥id
        char accessSecret[33] = "XXXXXXXXXXXXX&";//阿里短信密钥
        char Action[33] = "SendSms";
        char SignatureMethod[33] = "HMAC-SHA1";
        char SignatureVersion[16] = "1.0";
        char SignatureNonce[16] = {0};
        char Signature[64] = {0};
        char Version[16] = "2017-05-25";
        char RegionId[16] = "cn-hangzhou";
        char Timestamp[30] = {0};

        std::time_t rawTime;
        struct tm* timeInfo;
        time(&rawTime);
        timeInfo = gmtime(&rawTime);
        strftime(Timestamp,sizeof(Timestamp),"%Y-%m-%dT%H:%M:%SZ",timeInfo);
        snprintf(SignatureNonce,16 - 1 ,"%ld",std::time(NULL));

        std::string Url;
        Url.append(UrlEncode("AccessKeyId")).append("=").append(UrlEncode(AccessKeyId)).append("&").append(UrlEncode("Action")).append("=").append(UrlEncode(Action)).append("&Format=JSON").append("&").append(UrlEncode("PhoneNumbers")).append("=").append(UrlEncode(PhoneNumbers)).append("&").append("RegionId").append("=").append(RegionId);
        Url.append("&").append(UrlEncode("SignName")).append("=").append(UrlEncode(SignName)).append("&").append(UrlEncode("SignatureMethod")).append("=").append(UrlEncode(SignatureMethod));
        Url.append("&").append(UrlEncode("SignatureNonce")).append("=").append(UrlEncode(SignatureNonce)).append("&").append(UrlEncode("SignatureVersion")).append("=").append(UrlEncode(SignatureVersion)).append("&").append(UrlEncode("TemplateCode")).append("=").append(UrlEncode(TemplateCode));
        Url.append("&").append(UrlEncode("TemplateParam")).append("=").append(UrlEncode(TemplateParam)).append("&").append(UrlEncode("Timestamp")).append("=").append(UrlEncode(Timestamp));
        Url.append("&").append(UrlEncode("Version")).append("=").append(UrlEncode(Version));


        std::string strUrl1 = std::string("GET&").append(UrlEncode("/")).append("&").append(UrlEncode(std::string(Url)));
        std::string strUrl3 = replaceall(replaceall(replaceall(std::move(strUrl1),"%7E","~"),"*","%2A"),"+","%20");
        std::string Sgin = sgin(accessSecret,strUrl3.c_str());
        std::string strUrl4 = replaceall(replaceall(replaceall(UrlEncode(Sgin),"%7E","~"),"*","%2A"),"+","%20");
        url_parmas.append("?Signature=").append(strUrl4).append("&").append(Url);
    }

    std::string to_string()
    {
        return url_parmas;
    }
private:
    std::size_t wirtefunc( void *ptr, size_t size, size_t nmemb, void *stream)
    {
        return size * nmemb;
    }

    std::string replaceall(std::string&& str,const std::string& old_value,const std::string& new_value)
    {
        while(true){
            std::string::size_type   pos(0);
            if((pos = str.find(old_value)) != std::string::npos)
                str.replace(pos,old_value.length(),new_value);
            else break;
        }

        return str;
    }

    std::string UrlEncode(const std::string& szToEncode)
    {
        std::string src = szToEncode;
        char hex[] = "0123456789ABCDEF";
        std::string dst;

        for (size_t i = 0; i < src.size(); ++i)
        {
            unsigned char cc = src[i];
            if ( cc >= 'A' && cc <= 'Z'
                 || cc >='a' && cc <= 'z'
                 || cc >='0' && cc <= '9'
                 || cc == '.'
                 || cc == '_'
                 || cc == '-'
                 || cc == '*')
            {
                if (cc == ' ')
                {
                    dst += "+";
                }
                else
                    dst += cc;
            }
            else
            {
                unsigned char c = static_cast<unsigned char>(src[i]);
                dst += '%';
                dst += hex[c / 16];
                dst += hex[c % 16];
            }
        }
        return dst;
    }

    std::string sgin(const std::string& key, const char * data)
    {


        unsigned char digest[EVP_MAX_MD_SIZE + 1] = {'\0'};
        unsigned int digest_len = 0;

        HMAC(EVP_sha1(), key.c_str(), strlen(key.c_str()) + 1, (unsigned char*)data, std::strlen(data), digest, &digest_len);


//        char mdString[41] = {'\0'};

//        for(int i = 0; i < digest_len; i++)
//            sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

        return base64Encode(digest,digest_len);
    }

    std::string base64Encode(const unsigned char* Data,int DataByte)
    {
        //编码表
        const char EncodeTable[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        //返回值
        std::string strEncode;
        unsigned char Tmp[4]={0};
        int LineLength=0;
        for(int i=0;i<(int)(DataByte / 3);i++)
        {
            Tmp[1] = *Data++;
            Tmp[2] = *Data++;
            Tmp[3] = *Data++;
            strEncode+= EncodeTable[Tmp[1] >> 2];
            strEncode+= EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
            strEncode+= EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
            strEncode+= EncodeTable[Tmp[3] & 0x3F];
            if(LineLength+=4,LineLength==76) {strEncode+="\r\n";LineLength=0;}
        }
        //对剩余数据进行编码
        int Mod=DataByte % 3;
        if(Mod==1)
        {
            Tmp[1] = *Data++;
            strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
            strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4)];
            strEncode+= "==";
        }
        else if(Mod==2)
        {
            Tmp[1] = *Data++;
            Tmp[2] = *Data++;
            strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
            strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
            strEncode+= EncodeTable[((Tmp[2] & 0x0F) << 2)];
            strEncode+= "=";
        }

        return strEncode;
    }
private:
    std::string url_parmas;

};
#endif //CPP_SMS_ALIYUN_SMS_HPP
