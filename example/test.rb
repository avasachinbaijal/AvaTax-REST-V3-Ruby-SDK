require File.expand_path('../../lib/avalara_sdk', __FILE__)

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
  api_client = AvalaraSdk::ApiClient.new config
  api_instance = AvalaraSdk::ShippingVerificationApi.new api_client

  begin
    result =api_instance.deregister_shipment('DEFAULT', '063e1af4-11d3-4489-b8ba-ae1149758df4')
    p result
    puts "Call Completed" 
    
  rescue AvalaraSdk::ApiError => e
    puts "Exception #{e}"
  end

  puts "Success"