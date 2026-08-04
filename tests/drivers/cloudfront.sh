#!/usr/bin/env bats

# Copyright 2026 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

get_cloudfront_config() {
  if ! check_param_count_v2 "bucket name, root object, website endpoint" 3 $#; then
    return 1
  fi
  local bucket="$1" root_object="$2" website_endpoint="$3"
  local response file_name

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  cat > "$TEST_FILE_FOLDER/$file_name" <<EOF
{
  "CallerReference": "$(date +%s)",
  "Comment": "HTTPS distribution for ${bucket}",
  "Enabled": true,
  "DefaultRootObject": "${root_object}",
  "Origins": {
    "Quantity": 1,
    "Items": [
      {
        "Id": "s3-website-origin",
        "DomainName": "${website_endpoint}",
        "CustomOriginConfig": {
          "HTTPPort": 80,
          "HTTPSPort": 443,
          "OriginProtocolPolicy": "http-only",
          "OriginSslProtocols": {
            "Quantity": 1,
            "Items": ["TLSv1.2"]
          }
        }
      }
    ]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "s3-website-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 2,
      "Items": ["GET", "HEAD"],
      "CachedMethods": {
        "Quantity": 2,
        "Items": ["GET", "HEAD"]
      }
    },
    "Compress": true,
    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"
  },
  "PriceClass": "PriceClass_100",
  "HttpVersion": "http2",
  "IsIPV6Enabled": true
}
EOF

  printf '%s\n' "$TEST_FILE_FOLDER/$file_name"
  return 0
}

create_cloudfront_distribution() {
  if ! check_param_count_v2 "bucket name, root object, website endpoint" 3 $#; then
    return 1
  fi
  if [ -z "$DIRECT_CLOUDFRONT_TAG" ]; then
    log 2 "adding a cloudfront distribution in S3 test mode requires DIRECT_CLOUDFRONT_TAG env param to be set"
    return 1
  fi
  local bucket_name="$1" root_object="$2" website_endpoint="$3"
  local response config_file distribution_id distribution_domain

  if ! response=$(get_cloudfront_config "$bucket_name" "$root_object" "$website_endpoint" 2>&1); then
    log 2 "error getting cloudfront config file: $response"
    return 1
  fi
  config_file="$response"

  if ! response=$(put_cloudfront_user_policy 2>&1); then
    log 2 "error putting cloudfront user policy: $response"
    return 1
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront create-distribution \
      --distribution-config "file://${config_file}" --query 'Distribution.[Id,DomainName]' --output text 2>&1); then
    log 2 "error creating distribution: $response"
    return 1
  fi
  read -r distribution_id distribution_domain <<< "$response"

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront wait distribution-deployed --id "$distribution_id" 2>&1); then
    log 2 "error waiting for distribution to deploy: $response"
    return 1
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront tag-resource \
    --resource "arn:aws:cloudfront::${DIRECT_AWS_USER_ID}:distribution/${distribution_id}" \
    --tags 'Items=[{Key=Versitygw-Test,Value='"${DIRECT_CLOUDFRONT_TAG}"'}]' 2>&1); then
      log 2 "error tagging new distribution: $response"
      return 1
  fi

  printf '%s\n' "https://${distribution_domain}"
  return 0
}

put_cloudfront_user_policy() {
  log 6 "put_cloudfront_user_policy"
  local response file_name

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  cat > "$TEST_FILE_FOLDER/$file_name" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateCloudFrontDistribution",
      "Effect": "Allow",
      "Action": [
        "cloudfront:CreateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig",
        "cloudfront:ListDistributions",
        "cloudfront:ListTagsForResource",
        "cloudtrail:LookupEvents",
        "cloudfront:TagResource",
        "cloudfront:UpdateDistribution"
      ],
      "Resource": "*"
    }
  ]
}
EOF

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws iam put-user-policy \
      --user-name "$USER_ID_USER_1" --policy-name AllowCloudFrontTesting --policy-document "file://${TEST_FILE_FOLDER}/${file_name}" 2>&1); then
    log 2 "error putting user policy: $response"
    return 1
  fi
  return 0
}

delete_tester_created_distributions() {
  log 6 "get_user_created_distribution_ids"
  if ! check_param_count_v2 "s3 username" 1 $#; then
    return 1
  fi
  local username="$1"
  local response cloudtrail_data distribution_ids
  local -a distribution_id_array=()

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudtrail lookup-events \
      --region us-east-1 --lookup-attributes AttributeKey=Username,AttributeValue="${username}" --query 'Events[].CloudTrailEvent' --output text 2>&1); then
    log 2 "error getting distribution ids: $response"
    return 1
  fi
  cloudtrail_data="$response"

  if [ -n "$cloudtrail_data" ]; then
    return 0
  fi

  distribution_ids=$(jq -r -s '
        .[] | select(. != null) | try fromjson catch null
        | select(. != null and .eventSource == "cloudfront.amazonaws.com")
        | select(.eventName == "CreateDistribution" or .eventName == "CreateDistributionWithTags")
        | .responseElements.distribution.id
      ' <<< "$cloudtrail_data" 2>&1)
  log 5 "distribution ids: $distribution_ids"

  mapfile -t distribution_id_array <<< "$distribution_ids"
  for id in "${distribution_id_array[@]}"; do
    if ! delete_cloudfront_distribution "$id"; then
      log 2 "error deleting distribution"
      return 1
    fi
  done
  return 0
}

disable_cloudfront_distribution() {
  if ! check_param_count_v2 "config JSON, distribution ID, etag" 3 $#; then
    return 1
  fi
  local config_json="$1" distribution_id="$2" etag="$3"
  local response config_with_disable

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  config_with_disable="$TEST_FILE_FOLDER/$response"

  if ! response=$(jq '.DistributionConfig.Enabled = false | .DistributionConfig' <<< "$config_json" > "$config_with_disable" 2>&1); then
    log 2 "error locally writing new config with Enabled set to false: $response"
    return 1
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront update-distribution \
    --id "$distribution_id" --if-match "$etag" --distribution-config "file://${config_with_disable}" 2>&1); then
    log 2 "error updating distribution config: $response"
    return 1
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront wait distribution-deployed \
    --id "$distribution_id" 2>&1); then
    log 2 "error waiting for distribution disability: $response"
    return 1
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront get-distribution-config \
      --id "$distribution_id" --query ETag --output text 2>&1); then
    log 2 "error getting delete etag: $response"
    return 1
  fi
  etag="$response"
  echo "$etag"
  return 0
}

# return 2 for error, 1 for no match, 0 for match
check_for_cloudfront_tag() {
  if ! check_param_count_v2 "distribution ID" 1 $#; then
    return 2
  fi
  local distribution_id="$1"
  local distribution_arn response tag_value

  distribution_arn="arn:aws:cloudfront::${DIRECT_AWS_USER_ID}:distribution/${distribution_id}"
  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront list-tags-for-resource \
        --resource "$distribution_arn" \
        --query "Tags.Items[?Key=='Versitygw-Test' && Value=='${DIRECT_CLOUDFRONT_TAG}'].Value | [0]" \
        --output text 2>&1); then
    log 2 "error checking tag: $response"
    return 2
  fi
  tag_value="$response"

  if [ "$tag_value" != "$DIRECT_CLOUDFRONT_TAG" ]; then
    log 5 "skipping distribution with ID '${distribution_id}' (not tagged '$DIRECT_CLOUDFRONT_TAG')"
    return 1
  fi
  return 0
}

delete_cloudfront_distribution() {
  log 6 "delete_cloudfront_distribution: '$1'"
  if ! check_param_count_v2 "distribution ID" 1 $#; then
    return 1
  fi
  local distribution_id="$1"
  local response config_json enabled etag tag_check_result=0 config_with_disable deletion_etag

  if [ -z "$distribution_id" ] || [ "$distribution_id" == "null" ]; then
    return 0
  fi
  if ! response="$(env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront get-distribution-config --id "$distribution_id" 2>&1)"; then
    if  [[ "$response" == *"The specified distribution does not exist"* ]]; then
      return 0
    fi
    log 2 "error getting config for distribution with ID '$distribution_id': $response"
    return 1
  fi
  config_json="$response"
  enabled="$(jq -r '.DistributionConfig.Enabled' <<< "$config_json")"
  etag="$(jq -r '.ETag' <<< "$config_json")"

  check_for_cloudfront_tag "$distribution_id" || tag_check_result=$?
  if [ "$tag_check_result" -eq 2 ]; then
    log 2 "error checking for cloudfront tag"
    return 1
  elif [ "$tag_check_result" -eq 1 ]; then
    return 0
  fi

  if [ "$enabled" == "true" ]; then
    if ! response=$(disable_cloudfront_distribution "$config_json" "$distribution_id" "$etag" 2>&1); then
      log 2 "error deleting cloudfront distribution with id '$distribution_id': $response"
      return 1
    fi
    deletion_etag="$response"
  else
    deletion_etag="$etag"
  fi

  if ! response=$(send_command env AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true aws cloudfront delete-distribution \
      --id "$distribution_id" --if-match "$deletion_etag" 2>&1); then
    log 2 "error deleting distribution: $response"
    return 1
  fi

  log 5 "Deleted $distribution_id"
  return 0
}
