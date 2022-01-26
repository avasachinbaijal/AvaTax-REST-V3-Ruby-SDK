# AvalaraSdk::ErrorDetailsError

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **code** | **String** | Name of the error or message. | [optional] |
| **message** | **String** | Concise summary of the message, suitable for display in the caption of an alert box. | [optional] |
| **details** | [**ErrorDetailsErrorDetails**](ErrorDetailsErrorDetails.md) |  | [optional] |

## Example

```ruby
require 'avalara_sdk'

instance = AvalaraSdk::ErrorDetailsError.new(
  code: InvalidAddress,
  message: The address is not deliverable.,
  details: null
)
```

