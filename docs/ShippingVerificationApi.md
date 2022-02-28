# AvalaraSdk::ShippingVerificationApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
| ------ | ------------ | ----------- |
| [**deregister_shipment**](ShippingVerificationApi.md#deregister_shipment) | **DELETE** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration | Removes the transaction from consideration when evaluating regulations that span multiple transactions. |
| [**register_shipment**](ShippingVerificationApi.md#register_shipment) | **PUT** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration | Registers the transaction so that it may be included when evaluating regulations that span multiple transactions. |
| [**register_shipment_if_compliant**](ShippingVerificationApi.md#register_shipment_if_compliant) | **PUT** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registerIfCompliant | Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions. |
| [**verify_shipment**](ShippingVerificationApi.md#verify_shipment) | **GET** /api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/verify | Evaluates a transaction against a set of direct-to-consumer shipping regulations. |


## deregister_shipment

> deregister_shipment(company_code, transaction_code, opts)

Removes the transaction from consideration when evaluating regulations that span multiple transactions.

### Examples

```ruby
require 'time'
require 'avalara_sdk'
# setup authorization
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
api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

company_code = 'company_code_example' # String | The company code of the company that recorded the transaction
transaction_code = 'transaction_code_example' # String | The transaction code to retrieve
opts = {
  document_type: 'SalesInvoice' # String | (Optional): The document type of the transaction to operate on. If omitted, defaults to \"SalesInvoice\"
}

begin
  # Removes the transaction from consideration when evaluating regulations that span multiple transactions.
  api_instance.deregister_shipment(company_code, transaction_code, opts)
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->deregister_shipment: #{e}"
end
```

#### Using the deregister_shipment_with_http_info variant

This returns an Array which contains the response data (`nil` in this case), status code and headers.

> <Array(nil, Integer, Hash)> deregister_shipment_with_http_info(company_code, transaction_code, opts)

```ruby
begin
  # Removes the transaction from consideration when evaluating regulations that span multiple transactions.
  data, status_code, headers = api_instance.deregister_shipment_with_http_info(company_code, transaction_code, opts)
  p status_code # => 2xx
  p headers # => { ... }
  p data # => nil
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->deregister_shipment_with_http_info: #{e}"
end
```

### Parameters

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **company_code** | **String** | The company code of the company that recorded the transaction |  |
| **transaction_code** | **String** | The transaction code to retrieve |  |
| **document_type** | **String** | (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot; | [optional] |

### Return type

nil (empty response body)

### Authorization

[BasicAuth](../README.md#BasicAuth), [Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json


## register_shipment

> register_shipment(company_code, transaction_code, opts)

Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.

### Examples

```ruby
require 'time'
require 'avalara_sdk'
# setup authorization
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
api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

company_code = 'company_code_example' # String | The company code of the company that recorded the transaction
transaction_code = 'transaction_code_example' # String | The transaction code to retrieve
opts = {
  document_type: 'SalesInvoice' # String | (Optional): The document type of the transaction to operate on. If omitted, defaults to \"SalesInvoice\"
}

begin
  # Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
  api_instance.register_shipment(company_code, transaction_code, opts)
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->register_shipment: #{e}"
end
```

#### Using the register_shipment_with_http_info variant

This returns an Array which contains the response data (`nil` in this case), status code and headers.

> <Array(nil, Integer, Hash)> register_shipment_with_http_info(company_code, transaction_code, opts)

```ruby
begin
  # Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
  data, status_code, headers = api_instance.register_shipment_with_http_info(company_code, transaction_code, opts)
  p status_code # => 2xx
  p headers # => { ... }
  p data # => nil
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->register_shipment_with_http_info: #{e}"
end
```

### Parameters

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **company_code** | **String** | The company code of the company that recorded the transaction |  |
| **transaction_code** | **String** | The transaction code to retrieve |  |
| **document_type** | **String** | (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot; | [optional] |

### Return type

nil (empty response body)

### Authorization

[BasicAuth](../README.md#BasicAuth), [Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json


## register_shipment_if_compliant

> <ShippingVerifyResult> register_shipment_if_compliant(company_code, transaction_code, opts)

Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.

### Examples

```ruby
require 'time'
require 'avalara_sdk'
# setup authorization
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
api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

company_code = 'company_code_example' # String | The company code of the company that recorded the transaction
transaction_code = 'transaction_code_example' # String | The transaction code to retrieve
opts = {
  document_type: 'SalesInvoice' # String | (Optional): The document type of the transaction to operate on. If omitted, defaults to \"SalesInvoice\"
}

begin
  # Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
  result = api_instance.register_shipment_if_compliant(company_code, transaction_code, opts)
  p result
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->register_shipment_if_compliant: #{e}"
end
```

#### Using the register_shipment_if_compliant_with_http_info variant

This returns an Array which contains the response data, status code and headers.

> <Array(<ShippingVerifyResult>, Integer, Hash)> register_shipment_if_compliant_with_http_info(company_code, transaction_code, opts)

```ruby
begin
  # Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
  data, status_code, headers = api_instance.register_shipment_if_compliant_with_http_info(company_code, transaction_code, opts)
  p status_code # => 2xx
  p headers # => { ... }
  p data # => <ShippingVerifyResult>
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->register_shipment_if_compliant_with_http_info: #{e}"
end
```

### Parameters

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **company_code** | **String** | The company code of the company that recorded the transaction |  |
| **transaction_code** | **String** | The transaction code to retrieve |  |
| **document_type** | **String** | (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot; | [optional] |

### Return type

[**ShippingVerifyResult**](ShippingVerifyResult.md)

### Authorization

[BasicAuth](../README.md#BasicAuth), [Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json


## verify_shipment

> <ShippingVerifyResult> verify_shipment(company_code, transaction_code, opts)

Evaluates a transaction against a set of direct-to-consumer shipping regulations.

The transaction and its lines must meet the following criteria in order to be evaluated: * The transaction must be recorded. Using a type of *SalesInvoice* is recommended. * A parameter with the name *AlcoholRouteType* must be specified and the value must be one of the following: '*DTC*', '*Retailer DTC*' * A parameter with the name *RecipientName* must be specified and the value must be the name of the recipient. * Each alcohol line must include a *ContainerSize* parameter that describes the volume of a single container. Use the *unit* field to specify one of the following units: '*Litre*', '*Millilitre*', '*gallon (US fluid)*', '*quart (US fluid)*', '*ounce (fluid US customary)*' * Each alcohol line must include a *PackSize* parameter that describes the number of containers in a pack. Specify *Count* in the *unit* field.  Optionally, the transaction and its lines may use the following parameters: * The *ShipDate* parameter may be used if the date of shipment is different than the date of the transaction. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *RecipientDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *PurchaserDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *SalesLocation* parameter may be used to describe whether the sale was made *OnSite* or *OffSite*. *OffSite* is the default value. * The *AlcoholContent* parameter may be used to describe the alcohol percentage by volume of the item. Specify *Percentage* in the *unit* field.  **Security Policies** This API depends on all of the following active subscriptions: *AvaAlcohol, AutoAddress, AvaTaxPro*

### Examples

```ruby
require 'time'
require 'avalara_sdk'
# setup authorization
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
api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

company_code = 'company_code_example' # String | The company code of the company that recorded the transaction
transaction_code = 'transaction_code_example' # String | The transaction code to retrieve
opts = {
  document_type: 'SalesInvoice' # String | (Optional): The document type of the transaction to operate on. If omitted, defaults to \"SalesInvoice\"
}

begin
  # Evaluates a transaction against a set of direct-to-consumer shipping regulations.
  result = api_instance.verify_shipment(company_code, transaction_code, opts)
  p result
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->verify_shipment: #{e}"
end
```

#### Using the verify_shipment_with_http_info variant

This returns an Array which contains the response data, status code and headers.

> <Array(<ShippingVerifyResult>, Integer, Hash)> verify_shipment_with_http_info(company_code, transaction_code, opts)

```ruby
begin
  # Evaluates a transaction against a set of direct-to-consumer shipping regulations.
  data, status_code, headers = api_instance.verify_shipment_with_http_info(company_code, transaction_code, opts)
  p status_code # => 2xx
  p headers # => { ... }
  p data # => <ShippingVerifyResult>
rescue AvalaraSdk::ApiError => e
  puts "Error when calling ShippingVerificationApi->verify_shipment_with_http_info: #{e}"
end
```

### Parameters

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **company_code** | **String** | The company code of the company that recorded the transaction |  |
| **transaction_code** | **String** | The transaction code to retrieve |  |
| **document_type** | **String** | (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot; | [optional] |

### Return type

[**ShippingVerifyResult**](ShippingVerifyResult.md)

### Authorization

[BasicAuth](../README.md#BasicAuth), [Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

