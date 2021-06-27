async getIceServers(req, res) {

    var AWS = require('aws-sdk');
    var v4 = require('../utils/SigV4RequestSigner');

    const channelName = req.query.meetingId;
    const region = conf.aws_kinesis.region;
    const accessKeyId = conf.aws_kinesis.accessKeyId;
    const secretAccessKey = conf.aws_kinesis.secretAccessKey

    try {

      const kinesisVideoClient = new AWS.KinesisVideo({
        region,
        accessKeyId,
        secretAccessKey
      });

      const describeSignalingChannelResponse = await kinesisVideoClient
        .describeSignalingChannel({
          ChannelName: channelName,
        })
        .promise();

      const channelARN = describeSignalingChannelResponse.ChannelInfo.ChannelARN;

      const getSignalingChannelEndpointResponse = await kinesisVideoClient
        .getSignalingChannelEndpoint({
          ChannelARN: channelARN,
          SingleMasterChannelEndpointConfiguration: {
            Protocols: ['WSS', 'HTTPS'],
            Role: 'VIEWER',
          },
        })
        .promise();

      const endpointsByProtocol = getSignalingChannelEndpointResponse.ResourceEndpointList.reduce((endpoints, endpoint) => {
        endpoints[endpoint.Protocol] = endpoint.ResourceEndpoint;
        return endpoints;
      }, {});

      const kinesisVideoSignalingChannelsClient = new AWS.KinesisVideoSignalingChannels({
        region,
        accessKeyId,
        secretAccessKey,
        endpoint: endpointsByProtocol.HTTPS,
      });

      const getIceServerConfigResponse = await kinesisVideoSignalingChannelsClient
        .getIceServerConfig({
          ChannelARN: channelARN,
        })
        .promise();

      var parsedUrl = require('url').parse(endpointsByProtocol.WSS);

      var url = v4.createPresignedURL('GET',
        parsedUrl.host,
        parsedUrl.path ? parsedUrl.path : '/',
        'kinesisvideo',
        '',
        {
          key: accessKeyId,
          secret: secretAccessKey,
          protocol: 'wss',
          region: region,
          expires: 299,
          timestamp: require('moment').utc(),
          query: 'X-Amz-ChannelARN=' + channelARN + '&X-Amz-ClientId=' + require('crypto').randomBytes(10)
            .toString('base64').slice(0, 10)
        });

      return res.status(200).send({
        signalServer: url,
        iceServers: getIceServerConfigResponse.IceServerList
      });

    } catch (e) {
      console.error(e);
      return res.status(500).send(e);
    }
  }
