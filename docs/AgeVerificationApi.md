# AvalaraSDK::AgeVerificationApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
| ------ | ------------ | ----------- |
| [**verify_age**](AgeVerificationApi.md#verify_age) | **POST** /api/v2/ageverification/verify | Determines whether an individual meets or exceeds the minimum legal drinking age. |


## verify_age

> <AgeVerifyResult> verify_age(age_verify_request, opts)

Determines whether an individual meets or exceeds the minimum legal drinking age.

The request must meet the following criteria in order to be evaluated: * *firstName*, *lastName*, and *address* are required fields. * One of the following sets of attributes are required for the *address*:   * *line1, city, region*   * *line1, postalCode*  Optionally, the transaction and its lines may use the following parameters: * A *DOB* (Date of Birth) field. The value should be ISO-8601 compliant (e.g. 2020-07-21). * Beyond the required *address* fields above, a *country* field is permitted   * The valid values for this attribute are [*US, USA*]  **Security Policies** This API depends on the active subscription *AgeVerification*

### Examples

```ruby
require 'time'
require 'Avalara.SDK'
# setup authorization
AvalaraSDK.configure do |config|
  # Configure HTTP basic authorization: BasicAuth
  config.username = 'YOUR USERNAME'
  config.password = 'YOUR PASSWORD'

  # Configure API key authorization: Bearer
  config.api_key['Bearer'] = 'YOUR API KEY'
  # Uncomment the following line to set a prefix for the API key, e.g. 'Bearer' (defaults to nil)
  # config.api_key_prefix['Bearer'] = 'Bearer'
end

api_instance = AvalaraSDK::AgeVerificationApi.new
age_verify_request = AvalaraSDK::AgeVerifyRequest.new # AgeVerifyRequest | Information about the individual whose age is being verified.
opts = {
  simulated_failure_code: AvalaraSDK::AgeVerifyFailureCode::NOT_FOUND # AgeVerifyFailureCode | (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes.
}

begin
  # Determines whether an individual meets or exceeds the minimum legal drinking age.
  result = api_instance.verify_age(age_verify_request, opts)
  p result
rescue AvalaraSDK::ApiError => e
  puts "Error when calling AgeVerificationApi->verify_age: #{e}"
end
```

#### Using the verify_age_with_http_info variant

This returns an Array which contains the response data, status code and headers.

> <Array(<AgeVerifyResult>, Integer, Hash)> verify_age_with_http_info(age_verify_request, opts)

```ruby
begin
  # Determines whether an individual meets or exceeds the minimum legal drinking age.
  data, status_code, headers = api_instance.verify_age_with_http_info(age_verify_request, opts)
  p status_code # => 2xx
  p headers # => { ... }
  p data # => <AgeVerifyResult>
rescue AvalaraSDK::ApiError => e
  puts "Error when calling AgeVerificationApi->verify_age_with_http_info: #{e}"
end
```

### Parameters

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **age_verify_request** | [**AgeVerifyRequest**](AgeVerifyRequest.md) | Information about the individual whose age is being verified. |  |
| **simulated_failure_code** | [**AgeVerifyFailureCode**](.md) | (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes. | [optional] |

### Return type

[**AgeVerifyResult**](AgeVerifyResult.md)

### Authorization

[BasicAuth](../README.md#BasicAuth), [Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

