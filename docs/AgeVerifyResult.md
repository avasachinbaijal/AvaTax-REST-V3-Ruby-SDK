# AvalaraSdk::AgeVerifyResult

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **is_of_age** | **Boolean** | Describes whether the individual meets or exceeds the minimum legal drinking age. | [optional] |
| **failure_codes** | [**Array&lt;AgeVerifyResult&gt;**](AgeVerifyResult.md) | A list of failure codes describing why a *false* age determination was made. | [optional] |

## Example

```ruby
require 'avalara_sdk'

instance = AvalaraSdk::AgeVerifyResult.new(
  is_of_age: null,
  failure_codes: null
)
```

