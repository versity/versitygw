# Command-Line Tests

Instructions:
1. Build the `versitygw` binary.
2. Create a local AWS profile for connection to S3, and add the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values above to the profile.
3. Create an environment file (`.env`) similar to the ones in this folder, setting the `AWS_PROFILE` parameter to the name of the profile you created.
4. In the root repo folder, run with `VERSITYGW_TEST_ENV=<env file> tests/s3_bucket_tests.sh`.
5. If running/testing the GitHub workflow locally, create a `.secrets` file, and set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` parameters here to the values of your AWS S3 IAM account.
```
AWS_ACCESS_KEY_ID=<key_id>
AWS_SECRET_ACCESS_KEY=<secret_key>
```
6. To run the workflow locally, install **act** and run with `act -W .github/workflows/system.yml`.