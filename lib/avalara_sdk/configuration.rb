=begin
#Avalara Shipping Verification for Beverage Alcohol

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

=end


module AvalaraSdk
  class Configuration

    # Defines environment
    attr_accessor :environment

    # Defines Test base Path
    attr_accessor :test_base_path

    # Defines url base path
    attr_reader :base_path

    # Defines API keys used with API Key authentications.
    #
    # @return [Hash] key: parameter name, value: parameter value (API key)
    #
    # @example parameter name is "api_key", API key is "xxx" (e.g. "api_key=xxx" in query string)
    #   config.api_key['api_key'] = 'xxx'
    attr_accessor :api_key
    
    # Defines API key prefixes used with API Key authentications.
    #
    # @return [Hash] key: parameter name, value: API key prefix
    #
    # @example parameter name is "Authorization", API key prefix is "Token" (e.g. "Authorization: Token xxx" in headers)
    #   config.api_key_prefix['api_key'] = 'Token'
    attr_accessor :api_key_prefix

    # Defines the username used with HTTP basic authentication.
    #
    # @return [String]
    attr_accessor :username

    # Defines the password used with HTTP basic authentication.
    #
    # @return [String]
    attr_accessor :password

    # Defines override token URL for OAuth 2.0 flows when using the test environment.
    attr_accessor :test_token_url

    # Defines the ClientId used for the OAuth2 Client Credentials flow.
    attr_accessor :client_id

    # The ClientSecret used for the OAuth2 Client Credentials flow.
    attr_accessor :client_secret

    # The OAuth2 Avalara Identity Bearer Token that will be used for API access.
    attr_accessor :bearer_token

    # Set this to enable/disable debugging. When enabled (set to true), HTTP request/response
    # details will be logged with `logger.debug` (see the `logger` attribute).
    # Default to false.
    #
    # @return [true, false]
    attr_accessor :debugging

    # Defines the logger used for debugging.
    # Default to `Rails.logger` (when in Rails) or logging to STDOUT.
    #
    # @return [#debug]
    attr_accessor :logger

    # Defines the temporary folder to store downloaded files
    # (for API endpoints that have file response).
    # Default to use `Tempfile`.
    #
    # @return [String]
    attr_accessor :temp_folder_path

    # The time limit for HTTP request in seconds.
    # Default to 0 (never times out).
    attr_accessor :timeout

    # Set this to false to skip client side validation in the operation.
    # Default to true.
    # @return [true, false]
    attr_accessor :client_side_validation

    ### TLS/SSL setting
    # Set this to false to skip verifying SSL certificate when calling API from https server.
    # Default to true.
    #
    # @note Do NOT set it to false in production code, otherwise you would face multiple types of cryptographic attacks.
    #
    # @return [true, false]
    attr_accessor :verify_ssl

    ### TLS/SSL setting
    # Set this to false to skip verifying SSL host name
    # Default to true.
    #
    # @note Do NOT set it to false in production code, otherwise you would face multiple types of cryptographic attacks.
    #
    # @return [true, false]
    attr_accessor :verify_ssl_host

    ### TLS/SSL setting
    # Set this to customize the certificate file to verify the peer.
    #
    # @return [String] the path to the certificate file
    #
    # @see The `cainfo` option of Typhoeus, `--cert` option of libcurl. Related source code:
    # https://github.com/typhoeus/typhoeus/blob/master/lib/typhoeus/easy_factory.rb#L145
    attr_accessor :ssl_ca_cert

    ### TLS/SSL setting
    # Client certificate file (for client certificate)
    attr_accessor :cert_file

    ### TLS/SSL setting
    # Client private key file (for client certificate)
    attr_accessor :key_file

    # Set this to customize parameters encoding of array parameter with multi collectionFormat.
    # Default to nil.
    #
    # @see The params_encoding option of Ethon. Related source code:
    # https://github.com/typhoeus/ethon/blob/master/lib/ethon/easy/queryable.rb#L96
    attr_accessor :params_encoding

    attr_accessor :inject_format

    attr_accessor :force_ending_format

    # Defines the application name 
    #
    # @return [String]
    attr_accessor :app_name

    # Defines the application version 
    #
    # @return [String]
    attr_accessor :app_version

    # Defines the machine name 
    #
    # @return [String]
    attr_accessor :machine_name

    def initialize
      @base_path = ''
      @environment=''
      @app_name=''
      @app_version=''
      @machine_name=''
      @client_id=''
      @client_secret=''
      @bearer_token=''
      @test_base_path=''
      @test_token_url=''
      @username=''
      @password=''
      @api_key = {}
      @api_key_prefix = {}
      @client_side_validation = true
      @verify_ssl = true
      @verify_ssl_host = true
      @params_encoding = nil
      @cert_file = nil
      @key_file = nil
      @timeout = 0
      @debugging = false
      @inject_format = false
      @force_ending_format = false
      @logger = defined?(Rails) ? Rails.logger : Logger.new(STDOUT)

      yield(self) if block_given?
    end

    # The default Configuration object.
    def self.default
      @@default ||= Configuration.new
    end

    def configure
      yield(self) if block_given?
    end

    
    def base_path=(base_path)
      @base_path=base_path      
    end

    # Returns base URL for specified operation based on server settings
    def base_url
      case environment.downcase  
      when 'sandbox', 'qa'
        return 'https://sandbox-rest.avatax.com'
      when 'production'
        return 'https://rest.avatax.com'
      when 'test'
        if test_base_path.empty?
          fail ArgumentError, "Test_Base_Path must be configured to run in test environment mode."
        end
        return test_base_path
      else
        fail ArgumentError, "Invalid environment value"
      end
    end

    # Gets API key (with prefix if set).
    # @param [String] param_name the parameter name of API key auth
    def api_key_with_prefix(param_name, param_alias = nil)
      key = @api_key[param_name]
      key = @api_key.fetch(param_alias, key) unless param_alias.nil?
      if @api_key_prefix[param_name]
        "#{@api_key_prefix[param_name]} #{key}"
      else
        key
      end
    end

    # Gets Basic Auth token string
    def basic_auth_token
      'Basic ' + ["#{username}:#{password}"].pack('m').delete("\r\n")
    end

    # Returns Auth Settings hash for api client.
    def auth_settings
      {
        'BasicAuth' =>
          {
            type: 'basic',
            in: 'header',
            key: 'Authorization',
            value: basic_auth_token
          },
        'Bearer' =>
          {
            type: 'api_key',
            in: 'header',
            key: 'Authorization',
            value: api_key_with_prefix('Bearer')
          },
      }
    end
   
  end
end
