#!/usr/bin/env node
/**
 * VersityGW AWS SDK Compatibility Test
 *
 * Usage:
 *   npm install @aws-sdk/client-s3
 *   node sdk-test.mjs [options]
 *
 * Options (can also be set via environment variables):
 *   --endpoint   Gateway URL            (VGW_ENDPOINT,   default: http://localhost:7070)
 *   --access-key Root access key ID     (VGW_ACCESS_KEY, default: user)
 *   --secret-key Root secret access key (VGW_SECRET_KEY, default: password)
 *   --bucket     Bucket name to use     (VGW_BUCKET,     default: sdk-test-bucket)
 *   --region     AWS region             (VGW_REGION,     default: us-east-1)
 */

import {
  S3Client,
  ListBucketsCommand,
  CreateBucketCommand,
  PutObjectCommand,
  HeadObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  DeleteObjectCommand,
  DeleteBucketCommand,
} from "@aws-sdk/client-s3";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function arg(flag, envVar, defaultVal) {
  const idx = process.argv.indexOf(flag);
  if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
  return process.env[envVar] ?? defaultVal;
}

const ENDPOINT   = arg("--endpoint",   "VGW_ENDPOINT",   "http://localhost:7070");
const ACCESS_KEY = arg("--access-key", "VGW_ACCESS_KEY", "user");
const SECRET_KEY = arg("--secret-key", "VGW_SECRET_KEY", "password");
const BUCKET     = arg("--bucket",     "VGW_BUCKET",     "sdk-test-bucket");
const REGION     = arg("--region",     "VGW_REGION",     "us-east-1");

const client = new S3Client({
  endpoint: ENDPOINT,
  region: REGION,
  credentials: { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY },
  forcePathStyle: true,   // required for non-AWS S3-compatible gateways
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function pass(name) {
  console.log(`  [PASS] ${name}`);
  passed++;
}

function fail(name, err) {
  console.error(`  [FAIL] ${name}: ${err?.message ?? err}`);
  failed++;
}

async function run(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err);
  }
}

function streamToBuffer(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (c) => chunks.push(Buffer.from(c)));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function testListBuckets() {
  const res = await client.send(new ListBucketsCommand({}));
  if (!Array.isArray(res.Buckets)) throw new Error("Buckets is not an array");
}

async function testCreateBucket() {
  await client.send(new CreateBucketCommand({ Bucket: BUCKET }));
}

async function testHeadBucket() {
  await client.send(new HeadBucketCommand({ Bucket: BUCKET }));
}

async function testListBucketsContains() {
  const res = await client.send(new ListBucketsCommand({}));
  const found = res.Buckets.some((b) => b.Name === BUCKET);
  if (!found) throw new Error(`Bucket '${BUCKET}' not found in list`);
}

async function testPutObject() {
  await client.send(
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: "test-object.txt",
      Body: "Hello, VersityGW!",
      ContentType: "text/plain",
    })
  );
}

async function testHeadObject() {
  const res = await client.send(
    new HeadObjectCommand({ Bucket: BUCKET, Key: "test-object.txt" })
  );
  if (!res.ContentLength && res.ContentLength !== 0)
    throw new Error("Missing ContentLength in HeadObject response");
}

async function testGetObject() {
  const res = await client.send(
    new GetObjectCommand({ Bucket: BUCKET, Key: "test-object.txt" })
  );
  const body = await streamToBuffer(res.Body);
  const text = body.toString("utf-8");
  if (text !== "Hello, VersityGW!")
    throw new Error(`Unexpected body: ${JSON.stringify(text)}`);
}

async function testMultipartUpload() {
  const key = "multipart-object.bin";

  // Minimum part size is 5 MiB (except the last part).
  const PART_SIZE = 5 * 1024 * 1024;
  const part1 = Buffer.alloc(PART_SIZE, 0x61);  // 'a' * 5 MiB
  const part2 = Buffer.alloc(1024, 0x62);        // 'b' * 1 KiB  (last part, any size)

  // 1. Initiate
  const create = await client.send(
    new CreateMultipartUploadCommand({ Bucket: BUCKET, Key: key })
  );
  const uploadId = create.UploadId;
  if (!uploadId) throw new Error("No UploadId returned");

  let parts;
  try {
    // 2. Upload parts
    const [up1, up2] = await Promise.all([
      client.send(
        new UploadPartCommand({
          Bucket: BUCKET, Key: key, UploadId: uploadId,
          PartNumber: 1, Body: part1,
        })
      ),
      client.send(
        new UploadPartCommand({
          Bucket: BUCKET, Key: key, UploadId: uploadId,
          PartNumber: 2, Body: part2,
        })
      ),
    ]);

    parts = [
      { PartNumber: 1, ETag: up1.ETag },
      { PartNumber: 2, ETag: up2.ETag },
    ];

    // 3. Complete
    const complete = await client.send(
      new CompleteMultipartUploadCommand({
        Bucket: BUCKET,
        Key: key,
        UploadId: uploadId,
        MultipartUpload: { Parts: parts },
      })
    );
    if (!complete.ETag) throw new Error("No ETag in CompleteMultipartUpload response");

    // 4. Verify size via HeadObject
    const head = await client.send(new HeadObjectCommand({ Bucket: BUCKET, Key: key }));
    const expectedSize = PART_SIZE + 1024;
    if (head.ContentLength !== expectedSize)
      throw new Error(`Expected size ${expectedSize}, got ${head.ContentLength}`);
  } catch (err) {
    // Clean up the in-progress upload on failure
    await client.send(
      new AbortMultipartUploadCommand({ Bucket: BUCKET, Key: key, UploadId: uploadId })
    ).catch(() => {});
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async function cleanup() {
  for (const key of ["test-object.txt", "multipart-object.bin"]) {
    await client.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key })).catch(() => {});
  }
  await client.send(new DeleteBucketCommand({ Bucket: BUCKET })).catch(() => {});
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

console.log(`\nVersityGW SDK Compatibility Test`);
console.log(`  endpoint : ${ENDPOINT}`);
console.log(`  bucket   : ${BUCKET}`);
console.log(`  region   : ${REGION}\n`);

console.log("Running tests...");
await run("ListBuckets",               testListBuckets);
await run("CreateBucket",              testCreateBucket);
await run("HeadBucket",               testHeadBucket);
await run("ListBuckets (contains)",    testListBucketsContains);
await run("PutObject",                 testPutObject);
await run("HeadObject",                testHeadObject);
await run("GetObject",                 testGetObject);
await run("MultipartUpload",           testMultipartUpload);

console.log("\nCleaning up...");
await cleanup();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
