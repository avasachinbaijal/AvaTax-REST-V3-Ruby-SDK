# AvalaraSdk::ShippingVerifyResultLines

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **result_code** | **String** | Describes whether the line is compliant or not. In cases where a determination could not be made, resultCode will provide the reason why. | [optional] |
| **line_number** | **String** | The lineNumber of the line evaluated. | [optional] |
| **message** | **String** | A short description of the result of the checks made against this line. | [optional] |
| **success_messages** | **String** | A detailed description of the result of each of the passed checks made against this line. | [optional] |
| **failure_messages** | **String** | A detailed description of the result of each of the failed checks made against this line. | [optional] |
| **failure_codes** | **Array&lt;String&gt;** | An enumeration of all the failure codes received for this line. | [optional] |

## Example

```ruby
require 'avalara_sdk'

instance = AvalaraSdk::ShippingVerifyResultLines.new(
  result_code: null,
  line_number: null,
  message: null,
  success_messages: null,
  failure_messages: null,
  failure_codes: null
)
```

