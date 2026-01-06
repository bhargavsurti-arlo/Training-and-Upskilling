## Task-2 Documentation: Serverless App Using API Gateway, Lambda, and DynamoDB

### Overview

- **Goal**: Build a simple serverless backend API using AWS Console (GUI only).
- **Data store**: DynamoDB table `Products`.
- **Compute**: Lambda functions `AddItem`, `GetItem`, `ListItems`.
- **API layer**: API Gateway REST API with:
  - `POST /product` -> `AddItem`
  - `GET /product` -> `ListItems`
  - `GET /product/{id}` -> `GetItem`
- **Security**: IAM roles giving Lambdas permission to access DynamoDB.

---

## 1. Prerequisites

- **AWS account** with access to:
  - Lambda
  - DynamoDB
  - API Gateway
  - IAM
- Basic understanding of:
  - JSON
  - HTTP methods (`GET`, `POST`)

---

## 2. Create DynamoDB Table (`Products`)

1. Open the **AWS Management Console** and go to **DynamoDB**.
2. In the left navigation, click **Tables** -> **Create table**.
3. Configure the table:
   - **Table name**: `Products`
   - **Partition key**:
     - Name: `id`
     - Type: `String`
   - Leave **Sort key** empty.
4. Under **Table settings**:
   - Keep **Default settings**.
   - Use **On-demand** capacity for simplicity.
5. Click **Create table**.
6. Wait until the table's **Status** shows **Active**.

We have a `Products` table keyed by `id` (string).

---

## 3. Create Lambda Functions

We will create three Lambda functions using **Python 3.11**:

- **`AddItem`** - adds a new product to DynamoDB.
- **`GetItem`** - retrieves a product by its `id`.
- **`ListItems`** - lists all products.

> DynamoDB returns numbers as `Decimal` objects via `boto3`.  
> In `GetItem` and `ListItems`, we use a helper to convert `Decimal` values to `float` so `json.dumps()` can serialize them.

### 3.1 Create `AddItem` (Add product)

1. Open **Lambda** in the AWS Console.
2. Click **Create function**.
3. Choose **Author from scratch** and configure:
   - **Function name**: `AddItem`
   - **Runtime**: `Python 3.11`
   - **Architecture**: `x86_64`
   - **Execution role**: **Create a new role with basic Lambda permissions**.
4. Click **Create function**.
5. In the **Code** tab, replace the default code with:

```python
import json
import boto3
import uuid
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Products')

def lambda_handler(event, context):
    try:
        body_str = event.get("body") or "{}"
        body = json.loads(body_str)

        # Generate ID if not provided
        product_id = body.get("id") or str(uuid.uuid4())

        item = {
            "id": product_id,
            "name": body.get("name", ""),
            "price": body.get("price", 0),
            "description": body.get("description", ""),
            "created_at": datetime.utcnow().isoformat()
        }

        table.put_item(Item=item)

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "message": "Product added successfully",
                "product": item
            })
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": str(e)})
        }
```

6. Click **Deploy**.

---

### 3.2 Create `GetItem` (Get product by id)

1. In **Lambda**, click **Create function**.
2. Configure:
   - **Function name**: `GetItem`
   - **Runtime**: `Python 3.11`
   - **Execution role**: create a new role with basic Lambda permissions (or reuse later).
3. Click **Create function**.
4. Replace the default code with:

```python
import json
import boto3
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Products')

def convert_decimal(obj):
    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    if isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return float(obj)
    return obj

def lambda_handler(event, context):
    try:
        # Safely get path parameter
        path_params = event.get("pathParameters") or {}
        product_id = path_params.get("id")

        if not product_id:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps(
                    {"error": "Product ID is required in path /product/{id}"}
                )
            }

        response = table.get_item(Key={"id": product_id})

        if "Item" not in response:
            return {
                "statusCode": 404,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({"error": "Product not found"})
            }

        item = convert_decimal(response["Item"])

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(item)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": str(e)})
        }
```

5. Click **Deploy**.

---

### 3.3 Create `ListItems` (List all products)

1. In **Lambda**, click **Create function**.
2. Configure:
   - **Function name**: `ListItems`
   - **Runtime**: `Python 3.11`
3. Click **Create function**.
4. Replace the default code with:

```python
import json
import boto3
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Products')

def convert_decimal(obj):
    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    if isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return float(obj)
    return obj

def lambda_handler(event, context):
    try:
        response = table.scan()
        items = convert_decimal(response.get("Items", []))

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "count": len(items),
                "products": items
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": str(e)})
        }
```

5. Click **Deploy**.

---

## 4. Configure IAM Permissions (Lambda -> DynamoDB)

Each Lambda runs with an **execution role**. That role must be allowed to access the `Products` table.

### 4.1 Find each Lambda's role

For each function (`AddItem`, `GetItem`, `ListItems`):

1. Open the function in **Lambda**.
2. Go to **Configuration** -> **Permissions**.
3. Under **Execution role**, click the role name (e.g. `AddItem-role-xxxx`).
4. This opens the IAM role.

### 4.2 Attach DynamoDB permissions

Simple demo:

1. On the IAM role page, go to the **Permissions** tab.
2. Click **Add permissions** -> **Attach policies**.
3. Search for and select **`AmazonDynamoDBFullAccess`**.
4. Click **Next** -> **Add permissions**.


> In production, we will use a tighter custom policy:
> - `dynamodb:PutItem` for `AddItem`
> - `dynamodb:GetItem` for `GetItem`
> - `dynamodb:Scan` for `ListItems`
> on the specific `Products` table ARN.

---

## 5. Build the API with API Gateway

We create a REST API called **`ProductsAPI`** with routes:

- `POST /product` -> `AddItem`
- `GET /product` -> `ListItems`
- `GET /product/{id}` -> `GetItem`

### 5.1 Create the REST API

1. Open **API Gateway**.
2. Click **Create API**.
3. Under **REST API**, click **Build**.
4. Configure:
   - **API name**: `ProductsAPI`
   - **Endpoint type**: `Regional`
5. Click **Create API**.

---

### 5.2 Create `/product` resource

1. In the **Resources** tree, select root `/`.
2. Click **Actions** -> **Create resource**.
3. Configure:
   - **Resource name**: `product`
   - Ensure **Resource path** shows `/product`.
   - Optionally enable **CORS**.
4. Click **Create resource**.

---

### 5.3 Connect `POST /product` -> `AddItem`

1. Select `/product`.
2. Click **Actions** -> **Create method**.
3. Choose **POST**, then click the checkmark.
4. Configure:
   - **Integration type**: `Lambda Function`
   - **Use Lambda Proxy integration**: checked
   - **Region**: `YOUR_REGION`
   - **Lambda function**: `AddItem`
5. Click **Save** and confirm the permission prompt.

---

### 5.4 Connect `GET /product` -> `ListItems`

1. With `/product` selected, click **Actions** -> **Create method**.
2. Choose **GET**, then click the checkmark.
3. Configure:
   - **Integration type**: `Lambda Function`
   - **Use Lambda Proxy integration**: checked
   - **Lambda function**: `ListItems`
4. Click **Save** and confirm.

---

### 5.5 Create `/product/{id}` resource (path parameter)

1. In the **Resources** tree, select `/product`.
2. Click **Actions** -> **Create resource**.
3. Configure:
   - **Resource name**: `id`
   - **Resource path part**: type exactly `{id}` (with curly braces).
   - Confirm the parent path at the top is `/product/`.
4. Click **Create resource**.

We can see `/product/{id}` in the resources tree.

---

### 5.6 Connect `GET /product/{id}` -> `GetItem`

1. Select `/product/{id}`.
2. Click **Actions** -> **Create method**.
3. Choose **GET**, then click the checkmark.
4. Configure:
   - **Integration type**: `Lambda Function`
   - **Use Lambda Proxy integration**: checked
   - **Lambda function**: `GetItem`
5. Click **Save** and confirm the permission prompt.

---

### 5.7 (Optional) Enable CORS

1. Select `/product` -> **Actions** -> **Enable CORS**.
2. Allow:
   - **Origins**: `*` (or your domain).
   - **Methods**: `GET,POST,OPTIONS`.
3. Apply changes.
4. Repeat for `/product/{id}` if needed.
5. Deploy again after enabling CORS.

---

## 6. Deploy the API

1. In **API Gateway**, click **Actions** -> **Deploy API**.
2. For the first deployment:
   - **Deployment stage**: `[New Stage]`
   - **Stage name**: `prod` (or `test`).
3. Click **Deploy**.
4. Note the **Invoke URL**, for example:

   `https://API_ID.execute-api.REGION.amazonaws.com/prod`

Final routes:

- `POST https://API_ID.execute-api.REGION.amazonaws.com/prod/product`
- `GET  https://API_ID.execute-api.REGION.amazonaws.com/prod/product`
- `GET  https://API_ID.execute-api.REGION.amazonaws.com/prod/product/{id}`

---

## 7. Validation - How We Tested Everything

### 7.1 Validate `POST /product` (AddItem)

**API Gateway Test console:**

1. Select **POST** under `/product`.
2. Click **Test**.
3. In **Request body**, send:

```json
{
  "name": "Laptop",
  "price": 999.99,
  "description": "High-performance laptop"
}
```

4. Click **Test**.
5. Confirm:
   - Status code **200**.
   - Response body contains a `product` object with an auto-generated `id`.
   - The item appears in the DynamoDB `Products` table.

---

### 7.2 Validate `GET /product` (ListItems)

1. Select **GET** under `/product`.
2. Click **Test** (no body required).
3. Confirm:
   - Status code **200**.
   - JSON body with:
     - `count`: number of products.
     - `products`: array of product objects.
   - No `Object of type Decimal is not JSON serializable` error; the `convert_decimal` helper is working.

---

### 7.3 Validate `GET /product/{id}` (GetItem)

**API Gateway Test console:**

1. Select **GET** under `/product/{id}`.
2. Click **Test**.
3. In the **Path** section, find the field named `id`.
4. Paste the actual product ID returned from the `POST /product` call (e.g. `e2b6f0a4-...`).  
   - Do **not** type `/product/id` or `/product/`.
5. Click **Test**.
6. Confirm:
   - Status code **200**.
   - Response body contains that single product.

**External test with curl:**

# Add product
curl -X POST "https://API_ID.execute-api.REGION.amazonaws.com/prod/product" \
  -H "Content-Type: application/json" \
  -d '{"name":"Phone","price":499.99,"description":"New phone"}'

# List products
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/product"

# Get product by ID (replace ID_HERE with a real id)
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/product/ID_HERE"


8. Summary:

- **Implementation**
  - Created a **DynamoDB** table `Products` with primary key `id` (string).
  - Implemented three **Lambda** functions:
    - `AddItem`: inserts a new product document.
    - `GetItem`: retrieves a product by `id`, with robust error handling.
    - `ListItems`: scans and returns all products.
  - Configured **IAM roles** so each Lambda can read/write the `Products` table.
  - Built an **API Gateway REST API** (`ProductsAPI`) exposing:
    - `POST /product`
    - `GET /product`
    - `GET /product/{id}`

- **Validation**
  - Verified `POST /product` returns 200 and stores items in DynamoDB (checked via console).
  - Verified `GET /product` returns all items with valid JSON (no Decimal serialization errors).
  - Verified `GET /product/{id}` works when a real `id` is passed, returning 200 or appropriate 404/400 errors.
  - Confirmed all integration issues (Decimal handling, path parameter definition, and IAM permissions) were resolved.

This completes the detailed documentation for building and validating the serverless API using API Gateway, Lambda, DynamoDB, and IAM.


