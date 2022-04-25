=begin
#Avalara Shipping Verification for Beverage Alcohol

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

The version of the OpenAPI document: 2.1.0-beta

Generated by: https://openapi-generator.tech
OpenAPI Generator version: 5.3.1

=end

require 'spec_helper'
require 'json'

# Unit tests for AvalaraSdk::AgeVerificationApi
# Automatically generated by openapi-generator (https://openapi-generator.tech)
# Please update as you see appropriate
describe 'AgeVerificationApi' do
  before do
    config = AvalaraSdk::Configuration.new  
    config.username = ''
    config.password = ''
    config.environment='test'
    config.test_url='https://sandbox-rest.avatax.com'
    config.verify_ssl=false
    config.debugging=true
    config.app_name="testApp"
    config.app_version="2.3.1"
    config.machine_name="AVL_WIN_007"
    # run before each test
    @api_client = AvalaraSdk::ApiClient.new(config)
    @api_instance = AvalaraSdk::AgeVerification::AgeVerificationApi.new(@api_client)
  end

  after do
    # run after each test
  end

  describe 'test an instance of AgeVerificationApi' do
    it 'should create an instance of AgeVerificationApi' do
      expect(@api_instance).to be_instance_of(AvalaraSdk::AgeVerification::AgeVerificationApi)
    end
  end

  # unit tests for verify_age
  # Determines whether an individual meets or exceeds the minimum legal drinking age.
  # The request must meet the following criteria in order to be evaluated: * *firstName*, *lastName*, and *address* are required fields. * One of the following sets of attributes are required for the *address*:   * *line1, city, region*   * *line1, postalCode*  Optionally, the transaction and its lines may use the following parameters: * A *DOB* (Date of Birth) field. The value should be ISO-8601 compliant (e.g. 2020-07-21). * Beyond the required *address* fields above, a *country* field is permitted   * The valid values for this attribute are [*US, USA*]  **Security Policies** This API depends on the active subscription *AgeVerification*
  # @param age_verify_request Information about the individual whose age is being verified.
  # @param [Hash] opts the optional parameters
  # @option opts [AgeVerifyFailureCode] :simulated_failure_code (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes.
  # @return [AgeVerifyResult]
  describe 'verify_age test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

end
