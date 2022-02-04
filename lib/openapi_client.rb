=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.4.13-beta


=end

# Common files
require File.expand_path( '../openapi_client/api_client', __FILE__)
require File.expand_path( '../openapi_client/api_error', __FILE__)
require File.expand_path( '../openapi_client/version', __FILE__)
require File.expand_path( '../openapi_client/configuration', __FILE__)

# Models
require File.expand_path( '../openapi_client/models/age_verify_failure_code', __FILE__)
require File.expand_path( '../openapi_client/models/age_verify_request', __FILE__)
require File.expand_path( '../openapi_client/models/age_verify_request_address', __FILE__)
require File.expand_path( '../openapi_client/models/age_verify_result', __FILE__)
require File.expand_path( '../openapi_client/models/error_details', __FILE__)
require File.expand_path( '../openapi_client/models/error_details_error', __FILE__)
require File.expand_path( '../openapi_client/models/error_details_error_details', __FILE__)
require File.expand_path( '../openapi_client/models/shipping_verify_result', __FILE__)
require File.expand_path( '../openapi_client/models/shipping_verify_result_lines', __FILE__)

# APIs
require File.expand_path( '../openapi_client/api/age_verification_api', __FILE__)
require File.expand_path( '../openapi_client/api/shipping_verification_api', __FILE__)

module OpenapiClient
  class << self
    # Customize default settings for the SDK using block.
    #   OpenapiClient.configure do |config|
    #     config.username = "xxx"
    #     config.password = "xxx"
    #   end
    # If no block given, return the default Configuration object.
    def configure
      if block_given?
        yield(Configuration.default)
      else
        Configuration.default
      end
    end
  end
end
