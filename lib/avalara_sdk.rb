=begin

This is auto-generated class by sdk-generator 

=end

# All files
require File.expand_path( '../avalara_sdk/api_client.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api_error.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/AgeVerification/age_verification_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/shipping/shipping_verification_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/Shipping/shipping_verification_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/configuration.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_failure_code.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_request_address.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_request.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_result.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/Shipping/error_details_error_details.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/Shipping/error_details_error.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/Shipping/error_details.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/Shipping/shipping_verify_result_lines.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/Shipping/shipping_verify_result.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/version.rb', __FILE__) 


module AvalaraSdk
  class << self
    # Customize default settings for the SDK using block.
    #   AvalaraSdk.configure do |config|
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
