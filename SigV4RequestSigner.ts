"use strict";

var crypto = require("crypto");
var querystring = require("querystring");
var path = require("path");

exports.createCanonicalQueryString = function (params) {
    if (!params) {
        return "";
    }
    if (typeof params == "string") {
        params = querystring.parse(params);
    }
    return Object.keys(params)
        .sort()
        .map(function (key) {
            var values = Array.isArray(params[key]) ? params[key] : [params[key]];
            return values
                .sort()
                .map(function (val) {
                    return key + "=" + encodeRfc3986Full(val);
                })
                .join("&");
        })
        .join("&");
};

exports.createCredentialScope = function (time, region, service) {
    return [toDate(time), region, service, "aws4_request"].join("/");
};

exports.createSignatureKey = function (
    secret,
    time,
    region,
    service
) {
    var kDate = hmac("AWS4" + secret, toDate(time)); // date-key
    var kRegion = hmac(kDate, region); // region-key
    var kService = hmac(kRegion, service); // service-key
    var signingKey = hmac(kService, "aws4_request"); // signing-key
    return signingKey;
};

exports.createPresignedURL = function (
    method,
    host,
    path,
    service,
    payload,
    options
) {
    options = options || {};
    options.key = options.key || process.env.AWS_ACCESS_KEY_ID;
    options.secret = options.secret || process.env.AWS_SECRET_ACCESS_KEY;
    options.sessionToken = options.sessionToken || process.env.AWS_SESSION_TOKEN;
    options.protocol = options.protocol || "https";
    options.timestamp = options.timestamp || Date.now();
    options.region = options.region || process.env.AWS_REGION || "us-east-1";
    options.expires = options.expires || 86400; // 24 hours
    options.headers = options.headers || {};
    options.signSessionToken = options.signSessionToken || false;
    options.doubleEscape =
        options.doubleEscape !== undefined ? options.doubleEscape : true;

    // host is required
    options.headers.Host = host;

    var credentialScope = toDate(options.timestamp) + '/' + options.region + '/' + service + '/' + 'aws4_request';
    const signedHeaders = "host";

    var query = options.query ? querystring.parse(options.query) : {};
    query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256";
    query["X-Amz-Credential"] = options.key + "/" + credentialScope;
    query["X-Amz-Date"] = toTime(options.timestamp);
    query["X-Amz-Expires"] = options.expires;
    query["X-Amz-SignedHeaders"] = signedHeaders;

    var canonicalQueryString = exports.createCanonicalQueryString(query);
    const canonicalHeadersString = "host:" + host + "\n";

    // Prepare payload hash
    var payloadHash = sha256(payload);

    var canonicalRequest = method + '\n' + path + '\n' + canonicalQueryString + '\n'
        + canonicalHeadersString + '\n' + signedHeaders + '\n' + payloadHash;

    var canonicalRequestHash = sha256(canonicalRequest);

    var stringToSign = 'AWS4-HMAC-SHA256' + '\n' + toTime(options.timestamp) + '\n' + credentialScope + '\n' + canonicalRequestHash;

    var signingKey = exports.createSignatureKey(
        options.secret,
        options.timestamp,
        options.region,
        service
    );

    var signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

    query["X-Amz-Signature"] = signature;

    return (
        options.protocol + "://" + host + path + "?" + exports.createCanonicalQueryString(query)
    );
};

function toTime(time) {
    return new Date(time)
        .toISOString().replace(/[:\-]|\.\d{3}/g, '');
}

function toDate(time) {
    return toTime(time).substring(0, 8);
}

function sha256(string) {
    return crypto
        .createHash("sha256")
        .update(string, "utf8").digest('hex');
}

function hmac(key, string) {
    return crypto.createHmac('sha256', key).update(string, 'utf8').digest();
}

function encodeRfc3986(urlEncodedString) {
    return urlEncodedString.replace(/[!'()*]/g, function (c) {
        return '%' + c.charCodeAt(0).toString(16).toUpperCase()
    })
}

function encodeRfc3986Full(str) {
    return encodeRfc3986(encodeURIComponent(str))
}
