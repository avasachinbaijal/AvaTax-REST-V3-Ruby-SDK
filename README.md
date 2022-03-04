# avalara_sdk

AvalaraSdk - the Ruby gem for the Avalara Shipping Verification only

API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.

This API is currently in beta.


- Package version: 2.4.29

## Installation

```shell
gem install avalara_sdk
```

## Getting Started

Please follow the [installation](#installation) procedure and then run the following code:

```ruby
# Load the gem
require 'avalara_sdk'

# Setup authorization
AvalaraSdk.configure do |config|
  config.username = 'YOUR_USERNAME'
  config.password = 'YOUR_PASSWORD'
  config.environment='sandbox'
  config.verify_ssl=false
  config.app_name='testApp'
  config.app_version='1.2.3'
  config.machine_name='testMachine'


  config.username = 'YOUR_USERNAME'
  config.password = 'YOUR_PASSWORD'
  config.environment='sandbox'
  config.verify_ssl=false
  config.app_name='testApp'
  config.app_version='1.2.3'
  config.machine_name='testMachine'

end

api_client = AvalaraSdk::ApiClient.new config
api_instance = AvalaraSdk::AgeVerificationApi.new api_client

age_verify_request = AvalaraSdk::AgeVerifyRequest.new # AgeVerifyRequest | Information about the individual whose age is being verified.
opts = {
  simulated_failure_code: AvalaraSdk::AgeVerifyFailureCode::NOT_FOUND # AgeVerifyFailureCode | (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes.
}

begin
  #Determines whether an individual meets or exceeds the minimum legal drinking age.
  result = api_instance.verify_age(age_verify_request, opts)
  p result
rescue AvalaraSdk::ApiError => e
  puts "Exception when calling AgeVerificationApi->verify_age: #{e}"
end

```

## Documentation for API Endpoints

All URIs are relative to *http://localhost*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*AvalaraSdk::AgeVerificationApi* | [**verify_age**](docs/AgeVerificationApi.md#verify_age) | **POST** /api/v2/ageverification/verify | Determines whether an individual meets or exceeds the minimum legal drinking age.
*AvalaraSdk::ShippingVerificationApi* | [**deregister_shipment**](docs/ShippingVerificationApi.md#deregister_shipment) | **DELETE** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration | Removes the transaction from consideration when evaluating regulations that span multiple transactions.
*AvalaraSdk::ShippingVerificationApi* | [**register_shipment**](docs/ShippingVerificationApi.md#register_shipment) | **PUT** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration | Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
*AvalaraSdk::ShippingVerificationApi* | [**register_shipment_if_compliant**](docs/ShippingVerificationApi.md#register_shipment_if_compliant) | **PUT** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registerIfCompliant | Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
*AvalaraSdk::ShippingVerificationApi* | [**verify_shipment**](docs/ShippingVerificationApi.md#verify_shipment) | **GET** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/verify | Evaluates a transaction against a set of direct-to-consumer shipping regulations.


## Documentation for Models

 - [AvalaraSdk::AgeVerifyFailureCode](docs/AgeVerifyFailureCode.md)
 - [AvalaraSdk::AgeVerifyRequest](docs/AgeVerifyRequest.md)
 - [AvalaraSdk::AgeVerifyRequestAddress](docs/AgeVerifyRequestAddress.md)
 - [AvalaraSdk::AgeVerifyResult](docs/AgeVerifyResult.md)
 - [AvalaraSdk::ErrorDetails](docs/ErrorDetails.md)
 - [AvalaraSdk::ErrorDetailsError](docs/ErrorDetailsError.md)
 - [AvalaraSdk::ErrorDetailsErrorDetails](docs/ErrorDetailsErrorDetails.md)
 - [AvalaraSdk::ShippingVerifyResult](docs/ShippingVerifyResult.md)
 - [AvalaraSdk::ShippingVerifyResultLines](docs/ShippingVerifyResultLines.md)


## Documentation for Authorization


### BasicAuth

- **Type**: HTTP basic authentication

### Bearer


- **Type**: API key
- **API key parameter name**: Authorization
- **Location**: HTTP header

