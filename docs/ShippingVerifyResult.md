# OpenapiClient::ShippingVerifyResult

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **compliant** | **Boolean** | Whether every line in the transaction is compliant. | [optional] |
| **message** | **String** | A short description of the result of the compliance check. | [optional] |
| **success_messages** | **String** | A detailed description of the result of each of the passed checks made against this transaction, separated by line. | [optional] |
| **failure_messages** | **String** | A detailed description of the result of each of the failed checks made against this transaction, separated by line. | [optional] |
| **failure_codes** | **Array&lt;String&gt;** | An enumeration of all the failure codes received across all lines. | [optional] |
| **warning_codes** | **Array&lt;String&gt;** | An enumeration of all the warning codes received across all lines that a determination could not be made for. | [optional] |
| **lines** | [**Array&lt;ShippingVerifyResultLines&gt;**](ShippingVerifyResultLines.md) | Describes the results of the checks made for each line in the transaction. | [optional] |

## Example

```ruby
require 'openapi_client'

instance = OpenapiClient::ShippingVerifyResult.new(
  compliant: null,
  message: null,
  success_messages: null,
  failure_messages: null,
  failure_codes: null,
  warning_codes: null,
  lines: null
)
```

