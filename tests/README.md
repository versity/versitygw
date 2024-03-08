# Command-Line Tests

## Instructions - Running Locally

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

## Instructions - Running With Docker

1.  Create a `.secrets` file in the `tests` folder, and add the `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and the `AWS_PROFILE` fields.
2.  Build and run the `Dockerfile_test_bats` file.
