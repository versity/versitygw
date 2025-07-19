# REST scripts

## Parameters

The common S3 parameters for the scripts can be found in **rest.sh**.  They are:
* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_ENDPOINT_URL
* AWS_REGION

The `OUTPUT_FILE` parameter can be set to write the response data to a file.

Operation-specific parameters can be found by looking at the tops of the scripts.  For example, for the CreateBucket operation, this would be `BUCKET_NAME`.

## cURL

Most scripts will send a cURL message to an s3 server.  The scripts all use the following parameters:

In the root folder, for example, the **create_bucket.sh** script can be run with:

`AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<key> AWS_ENDPOINT_URL=<url> AWS_REGION=<region> BUCKET_NAME=<name> OUTPUT_FILE=<file> ./tests/rest_scripts/create_bucket.sh`

A successful bucket creation will return a 200 code on the command line.

## openssl

Some scripts will generate a raw REST API message that can be sent via openssl.

For example, to create this file with **put_object_openssl.sh**:

`AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<key> AWS_ENDPOINT_URL=<url> AWS_REGION=<region> DATA_FILE=<data_file> BUCKET_NAME=<name> OBJECT_KEY=<desired key name> COMMAND_FILE=<output file> ./tests/rest_scripts/put_object_openssl.sh`

This should generate a raw REST command file in the `COMMAND_FILE` location.  This command can be sent to the S3 server with:  `openssl s_client -connect <server host and port> -ign_eof < <command file>`
