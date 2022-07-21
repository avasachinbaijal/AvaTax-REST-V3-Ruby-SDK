require 'json'
require 'dotenv/load'

describe 'UserAPI' do
  before do
    config = AvalaraSdk::Configuration.new  
    config.client_id = ENV["CLIENT_ID"]
    # config.client_secret = ENV["CLIENT_SECRET"] || " "
    config.client_secret = " "
    config.environment='qa'
    config.app_name="testApp"
    config.app_version="2.3.1"
    config.machine_name="AVL_WIN_007"
    config.debugging=false
    config.verify_ssl_host=false
    config.verify_ssl=false
    @api_client = AvalaraSdk::ApiClient.new config
    @api_instance = AvalaraSdk::IAMDS::UserApi.new @api_client
  end

  describe 'test createUser endpoint' do
    it 'should be able to call createUser without exception' do
      begin
        result = @api_instance.create_user()
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
