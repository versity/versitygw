# Command-Line Tests

## Instructions - Running Locally

### Posix Backend

1. Build the `versitygw` binary.
2. Install the command-line interface(s) you want to test if unavailable on your machine.  
   * **aws cli**: Instructions are [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
   * **s3cmd**:  Instructions are [here](https://github.com/s3tools/s3cmd/blob/master/INSTALL.md).
   * **mc**:  Instructions are [here](https://min.io/docs/minio/linux/reference/minio-mc.html).
3. Install **BATS**.  Instructions are [here](https://bats-core.readthedocs.io/en/stable/installation.html).
4. Install **bats-support** and **bats-assert**.  This can be done by saving the root folder of each repo (https://github.com/bats-core/bats-support and https://github.com/ztombol/bats-assert) in the `tests` folder.
5. If running on Mac OS, install **jq** with the command `brew install jq`.
6. Create a `.secrets` file in the `tests` folder, and add the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and `AWS_PROFILE` values to the file.
7. Create a local AWS profile for connection to S3, and add the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION` values for your account to the profile.  Example:
```
    export AWS_PROFILE=versity-test
    export AWS_ACCESS_KEY_ID=<your account ID>
    export AWS_SECRET_ACCESS_KEY=<your account key>
    export AWS_REGION=<your account region>
    aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID --profile $AWS_PROFILE
    aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY --profile $AWS_PROFILE
    aws configure set aws_region $AWS_REGION --profile $AWS_PROFILE
```
8. Create an environment file (`.env`) similar to the ones in this folder, setting the `AWS_PROFILE` parameter to the name of the profile you created.
9. If using SSL, create a local private key and certificate, such as with the commands below.  Afterwards, set the `KEY` and `CERT` fields in the `.env` file to these, respectively.
```
    openssl genpkey -algorithm RSA -out versitygw.pem -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key versitygw.pem -out cert.pem -days 365
```
10. Set `BUCKET_ONE_NAME` and `BUCKET_TWO_NAME` to the desired names of your buckets.  If you don't want them to be created each time, set `RECREATE_BUCKETS` to `false`.
11. In the root repo folder, run single test group with `VERSITYGW_TEST_ENV=<env file> tests/run.sh <options>`.  To print options, run `tests/run.sh -h`.  To run all tests, run `VERSITYGW_TEST_ENV=<env file> tests/run_all.sh`.

### Static Bucket Mode

To preserve buckets while running tests, set `RECREATE_BUCKETS` to `false`.  Two utility functions are included, if needed, to create, and delete buckets for this:  `tests/setup_static.sh` and `tests/remove_static.sh`.  Note that this creates a bucket with object lock enabled, and some tests may fail if the bucket being tested doesn't have object lock enabled.

### S3 Backend

Instructions are mostly the same; however, testing with the S3 backend requires two S3 accounts.  Ideally, these are two real accounts, but one can also be a dummy account that versity uses internally.

To set up the latter:
1. Create a new AWS profile with ID and key values set to dummy 20-char allcaps and 40-char alphabetical values respectively.
2. In the `.secrets` file being used, create the fields `AWS_ACCESS_KEY_ID_TWO` and `AWS_SECRET_ACCESS_KEY_TWO`.  Set these values to the actual AWS ID and key.  
3. Set the values for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` the same dummy values set in the AWS profile, and set `AWS_PROFILE` to the profile you just created.
4. Create a new AWS profile with these dummy values.  In the `.env` file being used, set the `AWS_PROFILE` parameter to the name of this new profile, and the ID and key fields to the dummy values.  
5. Set `BACKEND` to `s3`.  Also, change the `MC_ALIAS` value if testing **mc** in this configuration.

### Direct Mode

To communicate directly with s3, in order to compare the gateway results to direct results:
1.  Create an AWS profile with the direct connection info.  Set `AWS_PROFILE` to this.
2.  Set `RUN_VERSITYGW` to false.
3.  Set `AWS_ENDPOINT_URL` to the typical endpoint location (usually `https://s3.amazonaws.com`).
4.  If testing **s3cmd**, create a new `s3cfg.local` file with `host_base` and `host_bucket` set to `s3.amazonaws.com`.
5.  If testing **mc**, change the `MC_ALIAS` value to a new value such as `versity-direct`.

## Instructions - Running With Docker

1.  Copy `.secrets.default` to `.secrets` in the `tests` folder and change the parameters and add the additional s3 fields explained in the **S3 Backend** section above if running with the s3 backend.
2.  By default, the dockerfile uses the **arm** architecture (usually modern Mac).  If using **amd** (usually earlier Mac or Linux), you can either replace the corresponding `ARG` values directly, or with `arg="<param>=<amd library or folder>"`  Also, you can determine which is used by your OS with `uname -a`.
3.  Build and run the `Dockerfile_test_bats` file.  Change the `SECRETS_FILE` and `CONFIG_FILE` parameters to point to your secrets and config file, respectively, if not using the defaults.  Example:  `docker build -t <tag> -f Dockerfile_test_bats --build-arg="SECRETS_FILE=<file>" --build-arg="CONFIG_FILE=<file>" .`.

## Instructions - Running with docker-compose

A file named `docker-compose-bats.yml` is provided in the root folder.  Four configurations are provided:
* insecure (without certificates), with creation/removal of buckets
* secure, posix backend, with static buckets
* secure, posix backend, with creation/removal of buckets
* secure, s3 backend, with creation/removal of buckets
* direct mode

To use each of these, creating a separate `.env` file for each is suggested.  How to do so is explained below.

To run in insecure mode, comment out the `CERT` and `KEY` parameters in the `.env` file, and change the prefix for the `AWS_ENDPOINT_URL` parameter to `http://`.  Also, set `S3CMD_CONFIG` to point to a copy of the default s3cmd config file that has `use_https` set to false.  Finally, change `MC_ALIAS` to something new to avoid overwriting the secure `MC_ALIAS` values.

To use static buckets set the `RECREATE_BUCKETS` value to `false`.

For the s3 backend, see the **S3 Backend** instructions above.

If using AMD rather than ARM architecture, add the corresponding **args** values matching those in the Dockerfile for **amd** libraries.

A single instance can be run with `docker-compose -f docker-compose-bats.yml up <service name>`