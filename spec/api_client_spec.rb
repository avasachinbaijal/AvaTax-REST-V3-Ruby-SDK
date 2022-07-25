# =begin
# #Avalara Shipping Verification only

# #API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

# SDK Version : 2.4.6


# =end

require 'avalara_sdk/token_metadata'
require 'dotenv/load'

describe AvalaraSdk::ApiClient do
  before(:all) do
    config = AvalaraSdk::Configuration.new
    config.client_id = ENV["CLIENT_ID"]
    config.client_secret = " "
    config.environment='qa'
    config.app_name="testApp"
    config.app_version="2.3.1"
    config.machine_name="AVL_WIN_007"
    @api_client = AvalaraSdk::ApiClient.new config
    @required_scopes ='avatax_api'
    @access_token ='test_token'
    @token_endpoint = 'https://ai-awsfqa.avlr.sh/connect/token'
    @expiry_time = 3600
  end

  before(:each) do
    # Mock OIDC Endpoint
    allow(Faraday).to receive(:get) {instance_double(Faraday::Response, body: "{ \"token_endpoint\": \"#{@token_endpoint}\" }")}
    # Mock Token endpoint
    allow(Faraday).to receive(:post) {instance_double(Faraday::Response, body:"{ \"access_token\": \"#{@access_token}\", \"expires_in\": #{@expiry_time} }")}
  end

  context "OAuth Helpers" do
    it "should get OAuth access token" do
      token = @api_client.get_oauth_access_token(@required_scopes)
      expect(token).to be_nil
      # Set timeout for 6 minutes, if the timeout is less than 5 minutes it will
      token_metadata = AvalaraSdk::TokenMetadata.new(@access_token, Time.now+360)
      @api_client.access_token_map['avatax_api'] = token_metadata
      token = @api_client.get_oauth_access_token(@required_scopes)
      expect(token).to eq(@access_token)
    end

    it "should not get expired OAuth access token" do
      # Set timeout for 4 minutes, if the timeout is less than 5 minutes it will
      token_metadata = AvalaraSdk::TokenMetadata.new(@access_token, Time.now+240)
      @api_client.access_token_map['avatax_api'] = token_metadata
      token = @api_client.get_oauth_access_token(@required_scopes)
      expect(token).to be_nil
    end

    it "should update OAuth access token" do
      @api_client.update_oauth_access_token @required_scopes, nil
      token = @api_client.get_oauth_access_token(@required_scopes)
      expect(token).to eq(@access_token)
    end

    it "should invalidate expired OAuth access token" do
      # invalidate expired token scenario
      allow(@api_client).to receive(:build_oauth_request).and_return({"access_token" => "new_token", "expires_in"=>@expiry_time })
      @api_client.update_oauth_access_token @required_scopes, @access_token
      token = @api_client.get_oauth_access_token(@required_scopes)
      expect(token).to eq("new_token")
    end
  end
end
