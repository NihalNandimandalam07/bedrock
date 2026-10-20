resource "aws_iam_role" "opa-lambda" {
  name = "opa-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}


resource "aws_iam_policy" "bedrock_policy" {
  name = "bedrock-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "bedrock:InvokeModel"
        Effect = "Allow"
        Resource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-5",     #change
          "arn:aws:bedrock:*:*:inference-profile/us.anthropic.claude-sonnet-5" #change
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_policy_attachment" {
  role       = aws_iam_role.opa-lambda.name
  policy_arn = aws_iam_policy.bedrock_policy.arn

  depends_on = [aws_iam_policy.bedrock_policy, aws_iam_role.opa-lambda]
}



resource "aws_iam_policy" "bedrock_marketplace_policy" {
  name = "bedrock-marketplace-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "aws-marketplace:ViewSubscriptions",
          "aws-marketplace:Subscribe"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_policy_marketplace_attachment" {
  role       = aws_iam_role.opa-lambda.name
  policy_arn = aws_iam_policy.bedrock_marketplace_policy.arn

  depends_on = [aws_iam_policy.bedrock_marketplace_policy, aws_iam_role.opa-lambda]
}




data "archive_file" "opa_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "opa_lambda" {
  function_name    = "opa-policy-generator"
  role             = aws_iam_role.opa-lambda.arn
  handler          = "lambda_function.lambda_handler" #change
  runtime          = "python3.13"
  filename         = data.archive_file.opa_lambda_zip.output_path
  source_code_hash = data.archive_file.opa_lambda_zip.output_base64sha256

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      BEDROCK_MODEL_ID = var.bedrock_model_id
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.bedrock_policy_attachment
  ]
}

/*
aws lambda invoke --function-name opa-policy-generator --cli-binary-format raw-in-base64-out --payload '{"requirement":"Generate an OPA policy that denies S3 buckets with public access."}' response2.json

python3 -c 'import json; r=json.load(open("response2.json")); assert r["statusCode"] == 200, r; print(json.loads(r["body"])["policy"])' > generated_policy2.rego
*/

