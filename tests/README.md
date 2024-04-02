# Command-Line Tests

## Instructions - Running Locally

### Posix Backend

1. Build the `versitygw` binary.
2. Install the command-line interface(s) you want to test if unavailable on your machine.  
   * **aws cli**: Instructions are [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
   * **s3cmd**:  Instructions are [here](https://github.com/s3tools/s3cmd/blob/master/INSTALL.md).
   * **mc**:  Instructions are [here](https://min.io/docs/minio/linux/reference/minio-mc.html).
3. Install BATS.  Instructions are [here](https://bats-core.readthedocs.io/en/stable/installation.html).
4. Create a `.secrets` file in the `tests` folder, and add the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values to the file.
5. Create a local AWS profile for connection to S3, and add the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION` values for your account to the profile.  Example:
```
    export AWS_PROFILE=versity-test
    export AWS_ACCESS_KEY_ID=<your account ID>
    export AWS_SECRET_ACCESS_KEY=<your account key>
    export AWS_REGION=<your account region>
    aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID --profile $AWS_PROFILE
    aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY --profile $AWS_PROFILE
    aws configure set aws_region $AWS_REGION --profile $AWS_PROFILE
```
6. Create an environment file (`.env`) similar to the ones in this folder, setting the `AWS_PROFILE` parameter to the name of the profile you created.
7. If using SSL, create a local private key and certificate, such as with the commands below.  Afterwards, set the `KEY` and `CERT` fields in the `.env` file to these, respectively.
```
    openssl genpkey -algorithm RSA -out versitygw.pem -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key versitygw.pem -out cert.pem -days 365
```
8. Set `BUCKET_ONE_NAME` and `BUCKET_TWO_NAME` to the desired names of your buckets.  If you don't want them to be created each time, set `RECREATE_BUCKETS` to `false`.
9. In the root repo folder, run single test group with `VERSITYGW_TEST_ENV=<env file> tests/run.sh <options>`.  To print options, run `tests/run.sh -h`.  To run all tests, run `VERSITYGW_TEST_ENV=<env file> tests/run_all.sh`.

### S3 Backend

Instructions are mostly the same; however, testing with the S3 backend requires two S3 accounts.  Ideally, these are two real accounts, but one can also be a dummy account that versity uses internally.

To set up the latter:
1. Create a new AWS profile with ID and key values set to dummy 20-char allcaps and 40-char alphabetical values respectively.
1. In the `.secrets` file being used, create the fields `AWS_ACCESS_KEY_ID_TWO` and `AWS_SECRET_ACCESS_KEY_TWO`.  Set these values to the actual AWS ID and key.  
2. Set the values for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` the same dummy values set in the AWS profile, and set `AWS_PROFILE` to the profile you just created.
3. Create a new AWS profile with these dummy values.  In the `.env` file being used, set the `AWS_PROFILE` parameter to the name of this new profile, and the ID and key fields to the dummy values.  
4. Set `BACKEND` to `s3`.  Also, change the `MC_ALIAS` value if testing **mc** in this configuration.

## Instructions - Running With Docker

1.  Create a `.secrets` file in the `tests` folder, and add the `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and the `AWS_PROFILE` fields.
2.  Build and run the `Dockerfile_test_bats` file.  Change the `SECRETS_FILE` and `CONFIG_FILE` parameters to point to an S3-backend-friendly config.  Example:  `docker build -t <tag> -f Dockerfile_test_bats --build-arg="SECRETS_FILE=<file>" --build-arg="CONFIG_FILE=<file>" .`.
