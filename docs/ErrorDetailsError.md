# OpenapiClient::ErrorDetailsError

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **code** | **String** | Name of the error or message. | [optional] |
| **message** | **String** | Concise summary of the message, suitable for display in the caption of an alert box. | [optional] |
| **details** | [**ErrorDetailsErrorDetails**](ErrorDetailsErrorDetails.md) |  | [optional] |

## Example

```ruby
require 'openapi_client'

instance = OpenapiClient::ErrorDetailsError.new(
  code: InvalidAddress,
  message: The address is not deliverable.,
  details: null
)
```

