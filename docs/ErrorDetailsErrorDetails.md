# OpenapiClient::ErrorDetailsErrorDetails

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **code** | **String** | Name of the error or message. | [optional] |
| **message** | **String** | Concise summary of the message, suitable for display in the caption of an alert box. | [optional] |
| **number** | **Integer** | Unique ID number referring to this error or message. | [optional] |
| **description** | **String** | A more detailed description of the problem referenced by this error message, suitable for display in the contents area of an alert box. | [optional] |
| **fault_code** | **String** | Indicates the SOAP Fault code, if this was related to an error that corresponded to AvaTax SOAP v1 behavior. | [optional] |
| **help_link** | **String** | URL to help for this message | [optional] |
| **severity** | **String** | Severity of the message | [optional] |

## Example

```ruby
require 'openapi_client'

instance = OpenapiClient::ErrorDetailsErrorDetails.new(
  code: InvalidAddress,
  message: The address is not deliverable.,
  number: 309,
  description: The physical location exists but there are no homes on this street. One reason might be railroad tracks or rivers running alongside this street, as they would prevent construction of homes in this location.,
  fault_code: Client,
  help_link: http://developer.avalara.com/avatax/errors/InvalidAddress,
  severity: Error
)
```

