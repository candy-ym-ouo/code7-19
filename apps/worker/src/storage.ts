import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client
} from "@aws-sdk/client-s3";
import { config } from "./config";

const credentials = {
  accessKeyId: config.S3_ACCESS_KEY,
  secretAccessKey: config.S3_SECRET_KEY
};

const s3 = new S3Client({
  endpoint: config.S3_ENDPOINT,
  region: config.S3_REGION,
  forcePathStyle: true,
  credentials
});

export async function readQuarantineObject(key: string): Promise<Buffer> {
  const response = await s3.send(new GetObjectCommand({
    Bucket: config.S3_QUARANTINE_BUCKET,
    Key: key
  }));
  if (!response.Body) throw new Error("Object body is empty");
  return Buffer.from(await response.Body.transformToByteArray());
}

export async function writeQuarantineObject(key: string, body: Buffer, contentType: string): Promise<void> {
  await s3.send(new PutObjectCommand({
    Bucket: config.S3_QUARANTINE_BUCKET,
    Key: key,
    Body: body,
    ContentType: contentType,
    CacheControl: "private, max-age=0"
  }));
}

export async function copyToPublic(processedKey: string, publicKey: string): Promise<void> {
  await s3.send(new CopyObjectCommand({
    Bucket: config.S3_PUBLIC_BUCKET,
    Key: publicKey,
    CopySource: `${config.S3_QUARANTINE_BUCKET}/${processedKey}`,
    MetadataDirective: "COPY"
  }));
}

export async function objectExists(bucket: string, key: string): Promise<boolean> {
  try {
    await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return true;
  } catch {
    return false;
  }
}

export async function deleteObject(bucket: string, key: string): Promise<void> {
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
}

export async function putExportObject(key: string, body: Buffer): Promise<void> {
  await s3.send(new PutObjectCommand({
    Bucket: config.S3_EXPORT_BUCKET,
    Key: key,
    Body: body,
    ContentType: "application/x-tar",
    CacheControl: "private, max-age=0"
  }));
}

export async function readExportObject(key: string): Promise<Buffer> {
  const response = await s3.send(new GetObjectCommand({
    Bucket: config.S3_EXPORT_BUCKET,
    Key: key
  }));
  if (!response.Body) throw new Error("Export object body is empty");
  return Buffer.from(await response.Body.transformToByteArray());
}

export async function exportObjectExists(key: string): Promise<boolean> {
  try {
    await s3.send(new HeadObjectCommand({ Bucket: config.S3_EXPORT_BUCKET, Key: key }));
    return true;
  } catch {
    return false;
  }
}

export async function deleteExportObject(key: string): Promise<void> {
  await s3.send(new DeleteObjectCommand({ Bucket: config.S3_EXPORT_BUCKET, Key: key }));
}
