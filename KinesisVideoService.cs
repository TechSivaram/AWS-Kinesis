using Amazon.KinesisVideo;
using Amazon.KinesisVideo.Model;
using Amazon.KinesisVideoSignalingChannels;
using Amazon.KinesisVideoSignalingChannels.Model;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Microsoft.Extensions.Options;
using PracticeInsights.Cloud.PatientChart.Api.Models;
using PracticeInsights.Cloud.PatientChart.Api.Models.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PracticeInsights.Cloud.PatientChart.Api.Services
{
    public class KinesisVideoService : BaseService
    {
        private readonly AwsKinesisConfig _awsKinesisConfig;

        public KinesisVideoService(IOptions<AwsKinesisConfig> options, IServiceProvider serviceProvider) : base(serviceProvider)
        {
            _awsKinesisConfig = options.Value;
        }

        internal async Task DeleteChannel(string channelName)
        {
            AmazonKinesisVideoClient vcl = new AmazonKinesisVideoClient(_awsKinesisConfig.AwsKey, _awsKinesisConfig.AwsSecret, Amazon.RegionEndpoint.USEast1);

            try
            {
                while (true)
                {
                    DescribeSignalingChannelRequest req = new DescribeSignalingChannelRequest
                    {
                        ChannelName = channelName
                    };

                    DescribeSignalingChannelResponse resp = await vcl.DescribeSignalingChannelAsync(req);

                    DeleteSignalingChannelRequest reqDC = new DeleteSignalingChannelRequest { ChannelARN = resp.ChannelInfo.ChannelARN };

                    await vcl.DeleteSignalingChannelAsync(reqDC);
                }
            }
            catch
            {

            }
        }

        internal async Task SendMeetingInvite(SendMeetingInviteDTO invite)
        {
            AmazonSimpleNotificationServiceClient snsClient = new AmazonSimpleNotificationServiceClient(_awsKinesisConfig.AwsKey, _awsKinesisConfig.AwsSecret, Amazon.RegionEndpoint.USEast1);

            PublishRequest pubRequest = new PublishRequest();

            pubRequest.MessageAttributes["AWS.SNS.SMS.SenderID"] = new MessageAttributeValue { StringValue = "Sivaram", DataType = "String" };
            pubRequest.MessageAttributes["AWS.SNS.SMS.SMSType"] = new MessageAttributeValue { StringValue = "Transactional", DataType = "String" };
            pubRequest.Message = invite.Message;
            pubRequest.PhoneNumber = "+1" + invite.PhoneNumber;

            PublishResponse pubResponse = await snsClient.PublishAsync(pubRequest);
        }

        public async Task<WebRTCParams> GetWebRTCParams(string channelName, bool isMaster, string viewerId)
        {
            AmazonKinesisVideoClient vcl = new AmazonKinesisVideoClient(_awsKinesisConfig.AwsKey, _awsKinesisConfig.AwsSecret, Amazon.RegionEndpoint.USEast1);
            string channelARN = "";

            if (isMaster)
            {
                try
                {
                    DescribeSignalingChannelRequest req = new DescribeSignalingChannelRequest
                    {
                        ChannelName = channelName
                    };

                    DescribeSignalingChannelResponse temp = vcl.DescribeSignalingChannelAsync(req).Result;
                    channelARN = temp.ChannelInfo.ChannelARN;
                    //DeleteSignalingChannelRequest reqDC = new DeleteSignalingChannelRequest
                    //{
                    //    ChannelARN = temp.ChannelInfo.ChannelARN
                    //};

                    //DeleteSignalingChannelResponse respDC = vcl.DeleteSignalingChannelAsync(reqDC).Result;
                }
                catch (Exception)
                {
                    CreateSignalingChannelRequest req = new CreateSignalingChannelRequest
                    {
                        ChannelName = channelName
                    };

                    CreateSignalingChannelResponse temp = vcl.CreateSignalingChannelAsync(req).Result;
                    channelARN = temp.ChannelARN;
                }
            }
            else
            {
                DescribeSignalingChannelRequest req = new DescribeSignalingChannelRequest
                {
                    ChannelName = channelName
                };

                DescribeSignalingChannelResponse temp = vcl.DescribeSignalingChannelAsync(req).Result;
                channelARN = temp.ChannelInfo.ChannelARN;
            }

            GetSignalingChannelEndpointRequest reqE = new GetSignalingChannelEndpointRequest
            {
                ChannelARN = channelARN,
                SingleMasterChannelEndpointConfiguration = new SingleMasterChannelEndpointConfiguration
                {
                    Protocols = new List<string> { "WSS", "HTTPS" },
                    Role = isMaster ? ChannelRole.MASTER : ChannelRole.VIEWER
                }
            };

            GetSignalingChannelEndpointResponse respE = vcl.GetSignalingChannelEndpointAsync(reqE).Result;

            string dataEndpoint = respE.ResourceEndpointList.First(i => i.Protocol == "HTTPS").ResourceEndpoint;

            GetIceServerConfigRequest reqICE = new GetIceServerConfigRequest
            {
                ChannelARN = channelARN
            };

            AmazonKinesisVideoSignalingChannelsConfig cfg = new AmazonKinesisVideoSignalingChannelsConfig
            {
                ServiceURL = dataEndpoint
            };

            AmazonKinesisVideoSignalingChannelsClient cl = new AmazonKinesisVideoSignalingChannelsClient(_awsKinesisConfig.AwsKey, _awsKinesisConfig.AwsSecret, cfg);
            GetIceServerConfigResponse resp = await cl.GetIceServerConfigAsync(reqICE);
            AWS4RequestSigner signer = new AWS4RequestSigner(_awsKinesisConfig.AwsKey, _awsKinesisConfig.AwsSecret);

            string signedUri;

            if (isMaster)
            {
                SortedDictionary<string, string> queryParams = new SortedDictionary<string, string>
                {
                    { "X-Amz-ChannelARN", channelARN }
                };
                string masterEndpoint = respE.ResourceEndpointList.First(i => i.Protocol == "WSS").ResourceEndpoint;
                signedUri = signer.GetSignedURL(masterEndpoint, queryParams);
            }
            else
            {
                SortedDictionary<string, string> queryParams = new SortedDictionary<string, string>
                {
                    { "X-Amz-ChannelARN", channelARN },
                    { "X-Amz-ClientId", viewerId }
                };
                string viewerEndpoint = respE.ResourceEndpointList.First(i => i.Protocol == "WSS").ResourceEndpoint;
                signedUri = signer.GetSignedURL(viewerEndpoint, queryParams);
            }

            return new WebRTCParams { SignalServer = signedUri, IceServers = resp.IceServerList };
        }
    }

    public class WebRTCParams
    {
        public string SignalServer { get; set; }
        public List<IceServer> IceServers { get; set; }
    }
}
