using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TechSivaram.Services
{
    /**
     * Utility class for SigV4 signing requests. The AWS SDK cannot be used for this purpose because it does not have support for WebSocket endpoints.
     */
    public class AWS4RequestSigner
    {
        private const string DEFAULT_ALGORITHM = "AWS4-HMAC-SHA256";
        private const string DEFAULT_SERVICE = "kinesisvideo";
        private const string DEFAULT_REGION = "us-east-1";
        private readonly string _service;
        private readonly string _region;
        private readonly string _awsAccessKey;
        private readonly string _awsSecretAccessKey;
        private readonly string DEFAULT_METHOD = "GET";

        public AWS4RequestSigner(string awsAccessKey, string awsSecretAccessKey, string region = DEFAULT_REGION, string service = DEFAULT_SERVICE)
        {
            _service = service;
            _region = region;
            _awsAccessKey = awsAccessKey;
            _awsSecretAccessKey = awsSecretAccessKey;
        }

        /**
         * Creates a SigV4 signed WebSocket URL for the given host/endpoint with the given query params.
         *
         * @param endpoint The WebSocket service endpoint including protocol, hostname, and path (if applicable).
         * @param queryParams Query parameters to include in the URL.
         * @param date Date to use for request signing. Defaults to NOW.
         *
         * Implementation note: Query parameters should be in alphabetical order.
         *
         * Note from AWS docs: "When you add the X-Amz-Security-Token parameter to the query string, some services require that you include this parameter in the
         * canonical (signed) request. For other services, you add this parameter at the end, after you calculate the signature. For details, see the API reference
         * documentation for that service." KVS Signaling Service requires that the session token is added to the canonical request.
         *
         * @see https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
         * @see https://gist.github.com/prestomation/24b959e51250a8723b9a5a4f70dcae08
         */
        public string GetSignedURL(string endpoint, SortedDictionary<string, string> queryParams)
        {
            // Prepare date strings
            DateTime date = DateTime.UtcNow;
            string datetimeString = getDateTimeString(date);
            string dateString = getDateString(date);

            // Validate and parse endpoint
            string protocol = "wss";
            string urlProtocol = $"{protocol}://";

            if (!endpoint.StartsWith(urlProtocol))
            {
                throw new Exception($"Endpoint {endpoint} is not a secure WebSocket endpoint.It should start with {urlProtocol}.");
            }

            if (endpoint.IndexOf("?") > 0)
            {
                throw new Exception($"Endpoint {endpoint} should not contain any query parameters.");
            }

            int pathStartIndex = endpoint.IndexOf('/', urlProtocol.Length);
            string host;
            string path;

            if (pathStartIndex < 0)
            {
                host = endpoint.Substring(urlProtocol.Length);
                path = "/";
            }
            else
            {
                host = endpoint.Substring(urlProtocol.Length, pathStartIndex);
                path = endpoint.Substring(pathStartIndex);
            }

            string signedHeaders = "host";

            // Prepare canonical query string
            string credentialScope = dateString + '/' + _region + '/' + _service + '/' + "aws4_request";
            SortedDictionary<string, string> canonicalQueryParams = new SortedDictionary<string, string>
            {
                { "X-Amz-Algorithm", DEFAULT_ALGORITHM },
                { "X-Amz-Credential", _awsAccessKey + "/" + credentialScope },
                { "X-Amz-Date", datetimeString },
                { "X-Amz-Expires", "299" },
                { "X-Amz-SignedHeaders", signedHeaders }
            };

            foreach (KeyValuePair<string, string> p in queryParams)
            {
                canonicalQueryParams.Add(p.Key, p.Value);
            }

            //    if private (this.credentials.sessionToken) {
            //Object.assign(canonicalQueryParams, {
            //    'X-Amz-Security-Token': this.credentials.sessionToken,
            //        });        

            string canonicalQueryString = createQueryString(canonicalQueryParams);

            // Prepare canonical headers
            //    private const canonicalHeaders = {
            //host,
            //    };
            string canonicalHeadersString = $"host:{host}\n";//createHeadersString(canonicalHeaders);

            // Prepare payload hash
            string payloadHash = sha256(string.Empty);

            // Combine canonical request parts into a canonical request string and hash
            string canonicalRequest = DEFAULT_METHOD + "\n" + path + "\n" + canonicalQueryString + "\n" + canonicalHeadersString + "\n" + signedHeaders + "\n" + payloadHash;
            string canonicalRequestHash = sha256(canonicalRequest);

            // Create signature
            string stringToSign = DEFAULT_ALGORITHM + "\n" + datetimeString + "\n" + credentialScope + "\n" + canonicalRequestHash;
            byte[] signingKey = getSignatureKey(_awsSecretAccessKey, dateString, _region, _service);
            string signature = toHex(hmac(signingKey, stringToSign));

            // Add signature to query params            

            SortedDictionary<string, string> signedQueryParams = new SortedDictionary<string, string>();
            foreach (KeyValuePair<string, string> p in canonicalQueryParams)
            {
                signedQueryParams.Add(p.Key, p.Value);
            }

            signedQueryParams.Add("X-Amz-Signature", signature);

            // Create signed URL
            return protocol + "://" + host + path + "?" + createQueryString(signedQueryParams);
        }

        /**
         * Utility method for generating the key to use for calculating the signature. This combines together the date string, region, service name, and secret
         * access key.
         *
         * @see https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
         */
        private byte[] getSignatureKey(string secretAccessKey, string dateString, string region, string service)
        {
            byte[] kDate = hmac("AWS4" + secretAccessKey, dateString);
            byte[] kRegion = hmac(kDate, region);
            byte[] kService = hmac(kRegion, service);

            return hmac(kService, "aws4_request");
        }

        /**
         * Utility method for converting a map of headers to a string for signing.
         */
        //private string createHeadersString(headers: Headers) : string {
        //    return Object.keys(headers)
        //        .private map(header => `${ header}:${headers[header]}\n`)
        //        .private join();
        //}

        /**
         * Utility method for converting a map of query parameters to a string with the parameter names sorted.
         */
        private string createQueryString(SortedDictionary<string, string> queryParams)
        {
            StringBuilder sb = new StringBuilder();

            foreach (KeyValuePair<string, string> v in queryParams)
            {
                sb.Append($"{v.Key}={encodeURIComponent(v.Value)}&");
            }

            string temp = sb.ToString();

            return temp.Substring(0, temp.Length - 1);
        }

        /**
         * Gets a datetime string for the given date to use for signing. For example: "20190927T165210Z"
         * @param date
         */
        private string getDateTimeString(DateTime date)
        {
            string Iso8601DateTimeFormat = "yyyyMMddTHHmmssZ";
            return date.ToString(Iso8601DateTimeFormat, CultureInfo.InvariantCulture);
        }

        /**
         * Gets a date string for the given date to use for signing. For example: "20190927"
         * @param date
         */
        private string getDateString(DateTime date)
        {
            string Iso8601DateFormat = "yyyyMMdd";
            return date.ToString(Iso8601DateFormat, CultureInfo.InvariantCulture);
        }

        private string sha256(string message)
        {
            return toHex(new SHA256CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(message)));
        }

        private byte[] hmac(string key, string value)
        {
            return hmac(Encoding.UTF8.GetBytes(key), value);
        }

        private byte[] hmac(byte[] key, string message)
        {
            KeyedHashAlgorithm mac = new HMACSHA256(key);
            mac.Initialize();
            return mac.ComputeHash(Encoding.UTF8.GetBytes(message));
        }

        /**
         * Note that this implementation does not work with two-byte characters.
         * However, no inputs into a signed signaling service request should have two-byte characters.
         */
        //private byte[] toUint8Array(string input) : Uint8Array {
        //        private const buf = new ArrayBuffer(input.length);
        //private const bufView = new Uint8Array(buf);
        //        for (let i = 0, strLen = input.length; i<strLen; i++) {
        //            bufView[i] = input.charCodeAt(i);
        //        }
        //        return bufView;
        //    }

        private string toHex(byte[] data)
        {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        public static string encodeURIComponent(string data)
        {
            string ValidUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            StringBuilder encoded = new StringBuilder();

            foreach (char symbol in Encoding.UTF8.GetBytes(data))
            {
                if (ValidUrlCharacters.IndexOf(symbol) != -1)
                {
                    encoded.Append(symbol);
                }
                else
                {
                    encoded.Append("%").Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", (int)symbol));
                }
            }

            return encoded.ToString();
        }
    }
}
