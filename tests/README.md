# Command-Line Tests

## Table of Contents

[Instructions - Running Locally](#instructions---running-locally)<br>
[* Posix Backend](#posix-backend)<br>
[* Static Bucket Mode](#static-bucket-mode)<br>
[* S3 Backend](#s3-backend)<br>
[* Direct Mode](#direct-mode)<br>
[Instructions - Running With Docker](#instructions---running-with-docker)<br>
[Instructions - Running With Docker-Compose](#instructions---running-with-docker-compose)<br>
[Environment Parameters](#environment-parameters)<br>
[* Secret](#secret)<br>
[* Non-Secret](#non-secret)<br>
[REST Scripts](#rest-scripts)<br>

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
4.  To run the entire suite, run `docker run -it <image name>`.  To run an individual suite, pass in the name of the suite as defined in `tests/run.sh` (e.g. REST tests -> `docker run -it <image name> rest`).  Also, multiple specific suites can be run, if separated by comma.

## Instructions - Running with docker-compose

A file named `docker-compose-bats.yml` is provided in the root folder.  A few configurations are provided, and you can also create your own provided you have a secrets and config file:
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

## Environment Parameters

### Secret

**AWS_PROFILE**, **AWS_ENDPOINT_URL**, **AWS_REGION**, **AWS_ACCESS_KEY_ID**, **AWS_SECRET_ACCESS_KEY**:  identical to the same parameters in **s3**.

**AWS_CANONICAL_ID**:  for direct mode, the canonical ID for the main user (owner)

**ACL_AWS_CANONICAL_ID**:  for direct mode, the canonical ID for the user to test ACL changes and access by non-owners

**ACL_AWS_ACCESS_KEY_ID**, **ACL_AWS_ACCESS_SECRET_KEY**:  for direct mode, the ID and key for the S3 user in the **ACL_AWS_CANONICAL_ID** account.

**USER_ID_{role}_{id}**, **USERNAME_{role}_{id}**, **PASSWORD_{role}_{id}**:  for setup_user_v2 non-autocreated users, the format for the user.
* example:  USER_ID_USER_1={name}:  user ID corresponding to the first user with **user** permissions in the test.

#### 

### Non-Secret

**VERSITY_EXE**:  location of the versity executable relative to test folder.

**RUN_VERSITYGW**:  whether to run the versitygw executable, should be set to **false** when running tests directly against **s3**.

**BACKEND**:  the storage backend type for the gateway, e.g. **posix** or **s3**.

**LOCAL_FOLDER**:  if running with a **posix** backend, the backend storage folder.

**BUCKET_ONE_NAME**, **BUCKET_TWO_NAME**:  test bucket names.

**RECREATE_BUCKETS**:  whether to delete buckets between tests.  If set to false, the bucket will be restored to an original state for the purpose of ensuring consistent tests, but not deleted.

**CERT**, **KEY**:  certificate and key locations if using SSL.

**S3CMD_CONFIG**:  location of **s3cmd** config file if running **s3cmd** tests.

**SECRETS_FILE**:  file where sensitive values, such as **AWS_SECRET_ACCESS_KEY**, should be stored.

**MC_ALIAS**:  Minio MC alias if running MC tests.

**LOG_LEVEL**:  level for test logger (1 - only critical, 2 - errors, 3 - warnings, 4 - info, 5 - debug info, 6 - tracing)

**GOCOVERDIR**:  folder to put golang coverage info in, if checking coverage info.

**USERS_FOLDER**:  folder to use if storing IAM data in a folder.

**IAM_TYPE**:  how to store IAM data (**s3** or **folder**).

**TEST_LOG_FILE**:  log file location for these bats tests.

**VERSITY_LOG_FILE**:  log file for versity application as it is tested by bats tests.

**DIRECT**:  if **true**, bypass versitygw and run directly against s3 (for comparison and validity-checking purposes).

**DIRECT_DISPLAY_NAME**:  AWS ACL main user display name if **DIRECT** is set to **true**.

**DIRECT_AWS_USER_ID**:  AWS policy 12-digit user ID if **DIRECT** is set to **true**.

**COVERAGE_DB**:  database to store client command coverage info and usage counts, if using.

**USERNAME_ONE**, **PASSWORD_ONE**, **USERNAME_TWO**, **PASSWORD_TWO**:  setup_user (v1), credentials for users created and tested for non-root user **versitygw** operations (non-setup_user_v2).

**TEST_FILE_FOLDER**:  where to put temporary test files.

**REMOVE_TEST_FILE_FOLDER**:  whether to delete the test file folder between tests, should be set to **true** unless checking the files after a single test, or not yet sure that the test folder is in a safe location to avoid deleting other files.

**VERSIONING_DIR**:  where to put gateway file versioning info.

**COMMAND_LOG**:  where to store list of client commands, which if using will be reported during test failures.

**TIME_LOG**:  optional log to show duration of individual tests

**DIRECT_S3_ROOT_ACCOUNT_NAME**:  for direct mode, S3 username for user with root permissions

**DELETE_BUCKETS_AFTER_TEST**:  whether or not to delete buckets after individual tests, useful for debugging if the post-test bucket state needs to be checked

**AUTOGENERATE_USERS**:  setup_user_v2, whether or not to autocreate users for tests.  If set to **false**, users must be pre-created (see `Secret` section above).

**USER_AUTOGENERATION_PREFIX**:  setup_user_v2, if **AUTOCREATE_USERS** is set to **true**, the prefix for the autocreated username. 

**CREATE_STATIC_USERS_IF_NONEXISTENT**:  setup_user_v2, if **AUTOCREATE_USERS** is set to **false**, generate non-existing users if they don't exist, but don't delete them, as with user autogeneration

**DIRECT_POST_COMMAND_DELAY**:  in direct mode, time to wait before sending new commands to try to prevent propagation delay issues

**SKIP_ACL_TESTING**:  avoid ACL tests for systems which do not use ACLs

**MAX_FILE_DOWNLOAD_CHUNK_SIZE**:  when set, will divide the download of large files with GetObject into chunks of the given size.  Useful for direct testing with slower connections.

## REST Scripts

REST scripts are included for calls to S3's REST API in the `./tests/rest_scripts/` folder.  To call a script, the following parameters are needed:
* **AWS_ACCESS_KEY_ID**, **AWS_SECRET_ACCESS_KEY**, etc.
* **AWS_ENDPOINT_URL** (default:  `https://localhost:7070`)
* **OUTPUT_FILE**:  file where the command's response data is written
* Any other parameters specified at the top of the script file, such as payloads and variables.  Sometimes, defaults are included.

Upon success, the script will return a response code, and write the data to the **OUTPUT_FILE** location.

Example:  `AWS_ACCESS_KEY_ID={id} AWS_SECRET_ACCESS_KEY={key} AWS_ENDPOINT_URL=https://s3.amazonaws.com OUTPUT_FILE=./output_file.xml ./tests/rest_scripts/list_buckets.sh`
