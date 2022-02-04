# OpenapiClient::AgeVerifyRequestAddress

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **line1** | **String** |  | [optional] |
| **city** | **String** |  | [optional] |
| **region** | **String** | The state code of the address. | [optional] |
| **country** | **String** | The country code of the address. | [optional] |
| **postal_code** | **String** |  | [optional] |

## Example

```ruby
require 'openapi_client'

instance = OpenapiClient::AgeVerifyRequestAddress.new(
  line1: null,
  city: null,
  region: null,
  country: null,
  postal_code: null
)
```

