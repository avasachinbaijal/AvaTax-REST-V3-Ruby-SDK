=begin

This is auto-generated class by sdk-generator 

=end

# All files
require File.expand_path( '../avalara_sdk/api_client.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api_error.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/AgeVerification/age_verification_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/app_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/device_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/entitlement_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/feature_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/grant_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/group_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/organization_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/permission_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/resource_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/role_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/system_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/tenant_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/IAMDS/user_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/api/shipping/shipping_verification_api.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/configuration.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_failure_code.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_request_address.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_request.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/AgeVerification/age_verify_result.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/app_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/app.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/aspect.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/contact_emails.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/contact_name.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/contact_phone_numbers.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/contact.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/device_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/device.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/entitlement_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/entitlement.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/feature_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/feature.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/grant_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/grant.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/group_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/group.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/instance_meta.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/instance.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/organization_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/organization.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/permission_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/permission.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/reference.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/resource_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/resource.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/role_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/role.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/system_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/system.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/tag.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/tenant_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/tenant.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/user_list.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/user.rb', __FILE__) 
require File.expand_path( '../avalara_sdk/models/IAMDS/version_error.rb', __FILE__) 
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
