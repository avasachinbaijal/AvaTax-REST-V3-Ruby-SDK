# avalara_sdk

AvalaraSdk - the Ruby gem for the Avalara Shipping Verification only

API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.

This API is currently in beta.


This SDK is automatically generated by the [OpenAPI Generator](https://openapi-generator.tech) project:

- API version: 3.1.0
- Package version: 2.3.8
- Build package: org.openapitools.codegen.languages.RubyClientCodegen

## Installation

### Build a gem

To build the Ruby code into a gem:

```shell
gem build avalara_sdk.gemspec
```

Then either install the gem locally:

```shell
gem install ./avalara_sdk-2.3.8.gem
```

(for development, run `gem install --dev ./avalara_sdk-2.3.8.gem` to install the development dependencies)

or publish the gem to a gem hosting service, e.g. [RubyGems](https://rubygems.org/).

Finally add this to the Gemfile:

    gem 'avalara_sdk', '~> 2.3.8'

### Install from Git

If the Ruby gem is hosted at a git repository: https://github.com/GIT_USER_ID/GIT_REPO_ID, then add the following in the Gemfile:

    gem 'avalara_sdk', :git => 'https://github.com/GIT_USER_ID/GIT_REPO_ID.git'

### Include the Ruby code directly

Include the Ruby code directly using `-I` as follows:

```shell
ruby -Ilib script.rb
```

## Getting Started

Please follow the [installation](#installation) procedure and then run the following code:

```ruby
# Load the gem
require 'avalara_sdk'

# Setup authorization
AvalaraSdk.configure do |config|
  # Configure HTTP basic authorization: BasicAuth
  config.username = 'YOUR_USERNAME'
  config.password = 'YOUR_PASSWORD'

  # Configure API key authorization: Bearer
  config.api_key['Bearer'] = 'YOUR API KEY'
  # Uncomment the following line to set a prefix for the API key, e.g. 'Bearer' (defaults to nil)
  # config.api_key_prefix['Bearer'] = 'Bearer'
end

api_instance = AvalaraSdk::AgeVerificationApi.new
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

