import argparse
import boto3
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
import io
from hashlib import md5
import json
from os import getenv
from pathlib import Path
import magic
from time import localtime
from urllib.request import urlopen
from botocore.exceptions import ClientError
import botocore

load_dotenv()

parser = argparse.ArgumentParser(prog='main.py',
                                 description="S3 Bucket Operations")
parser.add_argument('name', type=str, help='Bucket Name')
parser.add_argument('object_name', nargs="?", type=str, help="Object name")

parser.add_argument('-be',
                    '--bucket_exists',
                    action='store_true',
                    help='Check if bucket exists')
parser.add_argument('-cb',
                    '--create_bucket',
                    action='store_true',
                    help='Create new bucket')
parser.add_argument('-db',
                    '--delete_bucket',
                    action='store_true',
                    help='Delete bucket')
parser.add_argument('-go',
                    '--get_objects',
                    action='store_true',
                    help='Get objects in bucket')
parser.add_argument('-ceu',
                    '--count_extensions_usage',
                    action='store_true',
                    help='Count extensions usage')
parser.add_argument('-soap',
                    '--set_object_access_policy',
                    action='store_true',
                    help='Set object access policy')
parser.add_argument('-ap',
                    '--assign_policy',
                    action='store_true',
                    help='Assign policy')
parser.add_argument('-do',
                    '--delete_object',
                    action='store_true',
                    help='Delete object')
parser.add_argument('-rbp',
                    '--read_bucket_policy',
                    action='store_true',
                    help='Read bucket policy')
parser.add_argument("-ou",
                    "--object_url",
                    type=str,
                    help="link ",
                    default=None)
parser.add_argument("-dau",
                    "--download_and_upload",
                    choices=["False", "True"],
                    help="download and upload to bucket",
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-loc_o",
                    "--local_object",
                    type=str,
                    help="upload local object",
                    default=None)
parser.add_argument("-u_t",
                    "--upload_type",
                    type=str,
                    help="upload function type",
                    choices=[
                        "upload_file", "upload_fileobj", "put_object",
                        "multipart_upload"
                    ])

parser.add_argument("-arp",
                    "--assign_read_policy",
                    help="flag to assign read bucket policy.",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-amp",
                    "--assign_missing_policy",
                    help="flag to assign read bucket policy.",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument('-pbv',
                    '--versioning',
                    type=str,
                    default="Enabled",
                    help='Enable bucket ,versioning command')

parser.add_argument("-lv",
                    "--list_versions",
                    help="list versions",
                    action='store_true')

parser.add_argument("-rbt",
                    "--roll_back",
                    type=str,
                    help="rollback to",
                    default=None)

args = parser.parse_args()


def authenticate_client():
  client = boto3.client("s3",
                        aws_access_key_id=getenv("aws_access_key_id"),
                        aws_secret_access_key=getenv("aws_secret_access_key"),
                        aws_session_token=getenv("aws_session_token"),
                        region_name=getenv("aws_region_name"))
  return client


client = authenticate_client()


def bucket_list():
  return client.list_buckets()


def buckets_names():
  s3_buckets_list = bucket_list()
  for bucket in s3_buckets_list["Buckets"]:
    print(f'Bucket: {bucket["Name"]}')


def bucket_exists(bucket_name):
  s3_buckets_list = bucket_list()
  try:
    for bucket in s3_buckets_list["Buckets"]:
      if bucket["Name"] == bucket_name:
        return True
  except ClientError:
    return False



# def bucket_exists(bucket_name):
#     response = client.head_bucket(Bucket=bucket_name)
#     status = response["ResponseMetadata"]["HTTPStatusCode"]
#     if status == 200:
#         return True
#     else:
#         return False


def create_bucket(bucket_name):
  if (bucket_exists(bucket_name)):
    print(f"\nBucket '{bucket_name}' already exists\n")
    return False
  response = client.create_bucket(
      Bucket=bucket_name,
      CreateBucketConfiguration={
          'LocationConstraint': 'us-west-2',
      },
  )
  status = response["ResponseMetadata"]["HTTPStatusCode"]
  if status == 200:
    return True
  else:
    return False


def delete_bucket(bucket_name):
  response = client.delete_bucket(Bucket=bucket_name)
  status = response["ResponseMetadata"]["HTTPStatusCode"]
  if status == 204:
    return True
  else:
    return False


def get_objects(bucket_name):
  for key in client.list_objects(Bucket=bucket_name)['Contents']:
    print(f"{key['Key']}")


def count_extensions_usage(bucket_name):
  try:
    response = client.list_objects(Bucket=bucket_name)
  except client.exceptions.NoSuchBucket:
    return "Bucket does not exist"

  if 'Contents' not in response:
    return "No objects in the bucket"

  extensions_usage = defaultdict(lambda: {'count': 0, 'usage': 0.0})
  extension = None
  for obj in response['Contents']:
    key = obj['Key']
    size_bytes = obj['Size']
    size_mb = size_bytes / (1024 * 1024)

    extension = key.split('.')[-1]
    extensions_usage[extension]['count'] += 1
    extensions_usage[extension]['usage'] += size_mb

  return extension, extensions_usage[extension]['count'], extensions_usage[
      extension]['usage']


# object policy to read it
def set_object_access_policy(bucket_name, object_key):
  client.put_bucket_ownership_controls(
      Bucket=bucket_name,
      OwnershipControls={'Rules': [{
          'ObjectOwnership': 'ObjectWriter'
      }]})
  response = client.put_object_acl(ACL="public-read",
                                   Bucket=bucket_name,
                                   Key=object_key)
  status_code = response["ResponseMetadata"]["HTTPStatusCode"]
  if status_code == 200:
    return True
  return False


# bucket policy for get object
def public_read_policy(bucket_name):
  policy = policy = {
      "Version":
      "2012-10-17",
      "Statement": [{
          "Sid": "PublicReadGetObject",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": f"arn:aws:s3:::{bucket_name}/*",
      }],
  }
  return json.dumps(policy)


# bucket policy for multiple usage
def multiple_policy(bucket_name):
  policy = {
      "Version":
      "2012-10-17",
      "Statement": [{
          "Action": [
              "s3:ListBucketVersions", "s3:PutObjectAcl", "s3:GetObject",
              "s3:GetObjectAcl", "s3:DeleteObject"
          ],
          "Effect":
          "Allow",
          "Principal":
          "*",
          "Resource":
          [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]
      }]
  }
  return json.dumps(policy)


# assign bucket policy
def assign_policy(bucket_name, policy_function):
  policy = None
  response = None
  if policy_function == "public_read_policy":
    policy = public_read_policy(bucket_name)
    response = "public read policy assigned!"
  elif policy_function == "multiple_policy":
    policy = multiple_policy(bucket_name)
    response = "multiple policy assigned!"

  if (not policy):
    print('please provide policy')
    return

  client.delete_public_access_block(Bucket=bucket_name)
  client.put_bucket_policy(Bucket=bucket_name, Policy=policy)

  print(response)


def read_bucket_policy(bucket_name):
  try:
    policy = client.get_bucket_policy(Bucket=bucket_name)
    status_code = policy["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
      return policy["Policy"]
  except ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
      print("\nNo policy found for this bucket.")
      assign_policy(bucket_name, "public_read_policy")
  return False


def delete_object(bucket_name, object_name):
  try:
    response = client.delete_object(Bucket=bucket_name, Key=object_name)
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 204:
      return True
  except client.exceptions.NoSuchKey:
    print("Object does not exist")
    return False
  except client.exceptions.NoSuchBucket:
    print("Bucket does not exist")
    return False
  return False


def download_file_and_upload_to_s3(bucket_name, url, keep_local=True):
  mime_types = {
      "jpg": "image/jpeg",
      "csv": "text/csv",
      "jpeg": "image/jpeg",
      "png": "image/png",
      "mp4": "video/mp4",
      "mp3": "audio/mpeg",
      "pdf": "application/pdf",
      "doc": "application/msword"
  }

  with urlopen(url) as response:
    url_response = response.read()
    mime_type_of_url = magic.from_buffer(
        url_response, mime=True)  #returns mime type of the url

  file_type = None
  file_name = None

  for extension, ctype in mime_types.items():
    if mime_type_of_url == ctype:
      file_type = ctype
      timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
      file_name = f'file_{timestamp}.{extension}'

  if not file_type:
    raise ValueError("Invalid type")

  client.upload_fileobj(Fileobj=io.BytesIO(url_response),
                        Bucket=bucket_name,
                        ExtraArgs={'ContentType': file_type},
                        Key=file_name)

  if keep_local:
    with open(Path(f"{file_name}"), mode="wb") as file:
      file.write(url_response)

  return "https://s3-{0}.amazonaws.com/{1}/{2}".format('us-west-2',
                                                       bucket_name, file_name)


'''
python main.py btu-python-assignement1 -loc_o file_2.jpeg -u_t upload_fileobj
'''


def upload_local_file(bucket_name, filename, upload_type="upload_file"):

  mime_types = {
      "jpg": "image/jpeg",
      "csv": "text/csv",
      "jpeg": "image/jpeg",
      "png": "image/png",
      "mp4": "video/mp4",
      "mp3": "audio/mpeg",
      "pdf": "application/pdf",
      "doc": "application/msword"
  }

  file_path = Path(f"{filename}")
  mime_type = magic.from_file(file_path, mime=True)
  content_type = None
  file_name = None

  for extension, ctype in mime_types.items():
    if mime_type == ctype:
      content_type = ctype
      timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
      file_name = f'file_{timestamp}.{extension}'

  if not content_type:
    raise ValueError("Invalid type")

  if upload_type == "upload_file":
    client.upload_file(file_path,
                       bucket_name,
                       file_name,
                       ExtraArgs={'ContentType': content_type})
  elif upload_type == "upload_fileobj":
    with open(file_path, "rb") as file:
      client.upload_fileobj(file,
                            bucket_name,
                            file_name,
                            ExtraArgs={'ContentType': content_type})
  elif upload_type == "put_object":
    with open(file_path, "rb") as file:
      client.put_object(Body=file.read(),
                        Bucket=bucket_name,
                        Key=file_name,
                        ExtraArgs={'ContentType': content_type})


# public URL
  return "https://s3-{0}.amazonaws.com/{1}/{2}".format("us-west-2",
                                                       bucket_name, file_name)



'''
python main.py btu-python-assignement1 -pbv 'Suspended'
python main.py btu-python-assignement1 -pbv 'Enabled'
'''


def versioning(bucket_name, version):
  client.put_bucket_versioning(Bucket=bucket_name,
                               VersioningConfiguration={"Status": version})
  print(f"Versioning status set to {version}")


'''
python main.py btu-python-assignement1 file_20240423095056.jpeg -lv

'''


def list_object_versions(bucket_name, file_name):
  versions = client.list_object_versions(Bucket=bucket_name, Prefix=file_name)
  print(f"Versions in bucket '{bucket_name}':")
  for version in versions.get('Versions', []):
    print(f"  Object: {version['Key']}, Version ID: {version['VersionId']}, Size: {version['Size']}, Last Modified: {version['LastModified']}")


'''
python main.py <bucket_name> <object_name> -rbt <version_id>

'''


def rollback_to_version(bucket_name, file_name, versionID):
  client.copy_object(Bucket=bucket_name,
                     Key=file_name,
                     CopySource={
                         'Bucket': bucket_name,
                         'Key': file_name,
                         'VersionId': versionID
                     })
  print(f"Object '{file_name}' rolled back to version '{versionID}'")

def set_lifecycle_policy(bucket_name):

  lifecycle_policy = {
      'Rules': [
          {
              'ID': 'Delete after 120 days',
              'Status': 'Enabled',
              'Filter': {},  # Apply to all objects
              'Expiration': {
                  'Days': 120
              },
          }
      ]
  }
  try:
      client.put_bucket_lifecycle_configuration(
          Bucket=bucket_name,
          LifecycleConfiguration=lifecycle_policy
      )
      print(f"Lifecycle policy set for bucket {bucket_name}")
  except Exception as e:
      print(f"An error occurred: {e}")



def bucket_operations():
  # Bucket exists
  if args.bucket_exists:
    if (bucket_exists(args.name)):
      print(f"\nBucket '{args.name}' exists\n")
    else:
      print(f"\nBucket '{args.name}' does not exist\n")

  # Create bucket
  if args.create_bucket:
    if create_bucket(args.name):
      print(f"\nBucket '{args.name}' created successfully\n")
    else:
      print(f"\nBucket '{args.name}' creation failed\n")

  # Get objects
  if args.get_objects:
    print(f"\nObjects in bucket '{args.name}':")
    get_objects(args.name)

  # Count extensions usage
  if args.count_extensions_usage:
    extension, count, usage = count_extensions_usage(args.name)
    if extension:
      print(f'\nBucket {args.name} extensions usage: ')
      print(f'{extension}: {count}, usage: {usage:.2f} mb')

  # Delete bucket
  if args.delete_bucket:
    if delete_bucket(args.name):
      print(f"\nBucket '{args.name}' deleted successfully\n")
    else:
      print(f"\nBucket '{args.name}' deletion failed\n")

  # Set object access policy
  if args.set_object_access_policy:
    if set_object_access_policy(args.name, args.object_name):
      print(
          f"\nObject '{args.object_name}' in bucket '{args.name}' access policy set to public-read\n"
      )
    else:
      print(
          f"\nObject '{args.object_name}' in bucket '{args.name}' access policy set failed\n"
      )

  # Assign policy
  if args.assign_read_policy == "True":
    assign_policy(args.name, "public_read_policy")

  if args.assign_missing_policy == "True":
    assign_policy(args.name, "multiple_policy")

  # Read bucket policy
  if args.read_bucket_policy:
    policy = read_bucket_policy(args.name)
    if policy:
      print(f"\nBucket '{args.name}' policy: {policy}\n")
    else:
      print(f"\nBucket '{args.name}' policy read failed\n")

  # Download and upload to bucket
  if args.object_url and args.download_and_upload == "True":
    print(download_file_and_upload_to_s3(args.name, args.object_url))

  # Delete object
  if args.delete_object:
    if delete_object(args.name, args.object_name):
      print(
          f"\nObject '{args.object_name}' in bucket '{args.name}' deleted successfully\n"
      )
    else:
      print(
          f"\nObject '{args.object_name}' in bucket '{args.name}' deletion failed\n"
      )

  if args.local_object:
    print(upload_local_file(args.name, args.local_object, args.upload_type))

  if args.versioning:
    versioning(args.name, args.versioning)

  if args.list_versions:
    list_object_versions(args.name, args.object_name)

  if args.roll_back:
    rollback_to_version(args.name, args.object_name, args.roll_back)


if __name__ == "__main__":
  buckets_names()
  bucket_operations()