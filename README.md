# S3 Bucket Operations Application

## Overview

This Python application provides robust tools for managing Amazon S3 buckets through the command line. Leveraging the Boto3 library, it allows extensive manipulation of buckets and objects, including creation, deletion, listing, and policy management.

## Features

- **Bucket Management**: Check if buckets exist, create new buckets, and delete buckets.
- **Object Management**: Upload, delete, and list objects within buckets. Manage object policies and handle file types automatically.
- **Policy Management**: Assign, set, and read access policies for buckets and objects.
- **File Handling**: Download files from specified URLs and upload them directly to S3 buckets, with MIME type detection.
- **Versioning and Lifecycle Management**: Manage object versions and set lifecycle policies to automatically manage stored objects.

## Prerequisites

- Python 3.x
- Boto3 library
- dotenv (for environment variable management)
- Additional Python packages: `argparse`, `json`, `magic`, `io`
