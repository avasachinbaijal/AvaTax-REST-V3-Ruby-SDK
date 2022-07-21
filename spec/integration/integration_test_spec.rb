require 'json'
require 'dotenv/load'

describe 'ShipmentVerificationApi' do
  before do
    config = AvalaraSdk::Configuration.new  
    config.username = ENV["AUTH_USERNAME"]
    config.password = ENV["AUTH_PASSWORD"]
    config.environment='test'
    config.test_base_path='https://sandbox-rest.avatax.com'
    config.verify_ssl=false
    config.debugging=true
    config.app_name="testApp"
    config.app_version="2.3.1"
    config.machine_name="AVL_WIN_007"
    config.debugging=false
    @api_client = AvalaraSdk::ApiClient.new config
    @api_instance = AvalaraSdk::Shipping::ShippingVerificationApi.new @api_client
  end

  describe 'test verifyShipment endpoint' do
    it 'should be able to call verifyShipment without exception' do
      begin
        result = @api_instance.verify_shipment("DEFAULT", "7ded59c0-3ebd-4cc3-80f3-80018bd690b8")
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
  
