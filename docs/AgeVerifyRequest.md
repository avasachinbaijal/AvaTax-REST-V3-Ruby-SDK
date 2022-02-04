# OpenapiClient::AgeVerifyRequest

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **first_name** | **String** |  | [optional] |
| **last_name** | **String** |  | [optional] |
| **address** | [**AgeVerifyRequestAddress**](AgeVerifyRequestAddress.md) |  | [optional] |
| **dob** | **String** | The value should be ISO-8601 compliant (e.g. 2020-07-21). | [optional] |

## Example

```ruby
require 'openapi_client'

instance = OpenapiClient::AgeVerifyRequest.new(
  first_name: null,
  last_name: null,
  address: null,
  dob: null
)
```

