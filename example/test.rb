require File.expand_path('../../lib/avalara_sdk', __FILE__)

AvalaraSdk.configure do |config|
    # Configure HTTP basic authorization: BasicAuth
    config.username = 'demo.compliance-verification'
    config.password = 'sxgv7KK4HX*B7vY@'
    #config.base_path='https://sandbox-rest.avatax.com'
    # Uncomment the following line to set a prefix for the API key, e.g. 'Bearer' (defaults to nil)
    # config.api_key_prefix['Bearer'] = 'Bearer'
  end
  
  config = AvalaraSdk::Configuration.new  
  config.username = 'demo.compliance-verification'
  config.password = 'sxgv7KK4HX*B7vY@'
  #config.base_path='https://sandbox-rest.avatax.com'
  config.environment='sandbox'
  config.verify_ssl=false
  config.debugging=true
  config.app_name="testApp"
  config.app_version="2.3.1"
  config.machine_name="AVL_WIN_MAC"
  api_client = AvalaraSdk::ApiClient.new config
  api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

  begin
    result =api_instance.deregister_shipment('DEFAULT1', '063e1af4-11d3-4489-b8ba-ae1149758df4')
    p result
    puts "Call Completed" 
    
  rescue AvalaraSdk::ApiError => e
    puts "Exception #{e}"
  end

  puts "Success"