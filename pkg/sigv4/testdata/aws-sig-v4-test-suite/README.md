# Signature Version 4 Test Suite

To assist you in the development of an AWS client that supports Signature Version 4, you can use the files in the test suite to ensure your code is performing each step of the signing process correctly.

Each test group contains five files that you can use to validate each of the tasks described in Signature Version 4 Signing Process. The following list describes the contents of each file.

* `file-name.req` — the web request to be signed.
* `file-name.creq` — the resulting canonical request.
* `file-name.sts` — the resulting string to sign.
* `file-name.authz` — the Authorization header.
* `file-name.sreq` — the signed request.

## Credential Scope and Secret Key

The examples in the test suite use the following credential scope:

```
AKIDEXAMPLE/20150830/us-east-1/service/aws4_request
```

The example secret key used for signing is:

```
wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
```

## Example — A Simple GET Request with Parameters

The following example shows the web request to be signed from the `get-vanilla-query-order-key-case.req` file. This is the original request.

```
GET /?Param2=value2&Param1=value1 HTTP/1.1
Host:example.amazonaws.com
X-Amz-Date:20150830T123600Z
```

### Task 1: Create a Canonical Request

In the steps outlined in Task 1: Create a Canonical Request for Signature Version 4, change the request in the get-vanilla-query-order-key-case.req file.

```
GET /?Param2=value2&Param1=value1 HTTP/1.1
Host:example.amazonaws.com
X-Amz-Date:20150830T123600Z
```

This creates the canonical request in the `get-vanilla-query-order-key-case.creq` file.

```
GET
/
Param1=value1&Param2=value2
host:example.amazonaws.com
x-amz-date:20150830T123600Z

host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

#### Notes

* The parameters are sorted alphabetically (by character code).
* The header names are lowercase.
* There is a line break between the x-amz-date header and the signed headers.
* The hash of the payload is the hash of the empty string.

### Task 2: Create a String to Sign

The hash of the canonical request returns the following value:

```
816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0
```

In the steps outlined in Task 2: Create a String to Sign for Signature Version 4, add the algorithm, request date, credential scope, and the canonical request hash to create the string to sign.

The result is the `get-vanilla-query-order-key-case.sts` file.

```
AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/service/aws4_request
816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0
```

Notes

* The date on the second line matches the x-amz-date header, as well as the first element in the credential scope.
* The last line is the hex-encoded value for the hash of the canonical request.

### Task 3: Calculate the Signature

In the steps outlined in Task 3: Calculate the Signature for AWS Signature Version 4, create a signature with your signing key and the string to sign from the `get-vanilla-query-order-key-case.sts` file.

The result generates the contents in the `get-vanilla-query-order-key-case.authz` file.

```
AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500
```

### Task 4: Add the Signing Information to the Request

In the steps outlined in Task 4: Add the Signature to the HTTP Request, add the signing information generated in task 3 to the original request. For example, take the contents in the `get-vanilla-query-order-key-case.authz`, add it to the Authorization header, and then add the result to the `get-vanilla-query-order-key-case.req`.

This creates the signed request in the get-vanilla-query-order-key-case.sreq file.

```
GET /?Param2=value2&Param1=value1 HTTP/1.1
Host:example.amazonaws.com
X-Amz-Date:20150830T123600Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service
```
