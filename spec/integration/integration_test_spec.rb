require 'spec_helper'
require 'json'

describe 'ShipmentVerificationApi' do
  before do
    config = AvalaraSdk::Configuration.new  
    config.username = ENV["USERNAME"]
    config.password = ENV["PASSWORD"]
    config.environment='test'
    config.test_url='https://sandbox-rest.avatax.com'
    config.verify_ssl=false
    config.debugging=true
    config.app_name="testApp"
    config.app_version="2.3.1"
    config.machine_name="AVL_WIN_007"
    @api_client = AvalaraSdk::ApiClient.new config
    @api_instance = AvalaraSdk::ShippingVerificationApi.new @api_client
  end

  describe 'test verifyShipment endpoint' do
    it 'should be able to call verifyShipment without exception' do
      begin
        result = @api_instance.verify_shipment("DEFAULT", "063e1af4-11d3-4489-b8ba-ae1149758df4")
        p result
        puts "Call Completed" 
      rescue AvalaraSdk::ApiError => e
        puts "Exception #{e}"
        @exception = true
      end
      expect(@exception).to be_nil
    end
  end

end
  