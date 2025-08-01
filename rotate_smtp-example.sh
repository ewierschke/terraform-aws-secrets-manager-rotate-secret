#!/bin/bash

#Application specific scripts assumed to be pre-created on EC2 instance
#should not pass secret values from lambda to EC2 instance via ssm send_command,
#only secret arn to be queried for AWSPENDING stage label here/locally on ec2
#
#potential to have lambda query for success flag (SMTPPASSWORDUPDATESUCCESSFUL) in stdout to
#determine success or potentially just check for invocation success

if [ -z "$1" ]; then
    echo "Error: Need to provide SecretId as script parameter, cannot be empty."
    exit 1
fi

SECRET_CONTENT=$(aws secretsmanager get-secret-value --secret-id "$1" --version-stage "AWSPENDING" --query 'SecretString' --output text)

if [ -z "$SECRET_CONTENT" ]; then
    echo "Exiting. We were not able to get the secret content from AWS Secret Manager" >&2
    exit 1
fi

#SecretString content structure assumed to contain AccessKeyID and SMTPPassword key/value pairs
SMTP_USER=$(echo $SECRET_CONTENT | jq -r .AccessKeyId)
SMTP_PASS=$(echo $SECRET_CONTENT | jq -r .SMTPPassword)

##do stuff here to update application with new values, check for errors on last

#some other stuff then a final check for success/fail
RESULT=$(echo $SMTP_USER >> /tmp/smtp_user)

#only put specific flag into send_command stdout if successful; for potential lambda search
if [ $? -eq 0 ]; then
  echo "SMTPPASSWORDUPDATESUCCESSFUL"
else
  echo "Updating failed."
  exit 1
fi
