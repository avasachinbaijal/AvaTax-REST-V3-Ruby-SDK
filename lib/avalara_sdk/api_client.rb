=begin
#Avalara Shipping Verification for Beverage Alcohol

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

The version of the OpenAPI document: 2.1.0-beta

Generated by: https://openapi-generator.tech
OpenAPI Generator version: 5.3.1

=end

require 'date'
require 'json'
require 'logger'
require 'tempfile'
require 'time'
require 'base64'
require 'uri'
require 'faraday'
require 'avalara_sdk/token_metadata'
require 'avalara_sdk/response_hash'

module AvalaraSdk
  class ApiClient
    PRODUCTION_OPENID_CONFIG_URL = 'https://identity.avalara.com/.well-known/openid-configuration'
    SANDBOX_OPENID_CONFIG_URL = 'https://ai-sbx.avlr.sh/.well-known/openid-configuration'
    QA_OPENID_CONFIG_URL = 'https://ai-awsfqa.avlr.sh/.well-known/openid-configuration'

    # The Configuration object holding settings to be used in the API client.
    attr_accessor :config

    # The sdk version to be set in header
    attr_accessor :sdk_version

    # Defines the headers to be used in HTTP requests of all API calls by default.
    #
    # @return [Hash]
    attr_accessor :default_headers

    # The token url that will be used for the OAuth2 flows
    attr_accessor :token_url

    # The in-memory cache for access tokens
    attr_accessor :access_token_map

    # Initializes the ApiClient
    # @option config [Configuration] Configuration for initializing the object, default to Configuration.default
    def initialize(config)

      if (config.nil?)
        fail ArgumentError,'configuration is nil'
      end

      @base_path=config.base_url()
      @sdk_version=""
      @config = config
      @default_headers = {
        'Content-Type' => 'application/json',
        'User-Agent' => @user_agent
      }
      @access_token_map = Hash.new
      @token_url=""

    end

    def self.default
      @@default ||= ApiClient.new(@config)
    end

    def set_sdk_version(sdk_version="")
      @sdk_version=sdk_version
    end

    # Call an API with given options.
    #
    # @return [Array<(Object, Integer, Hash)>] an array of 3 elements:
    #   the data from response body (could be nil), response status code and response headers.
    def call_api(http_method, path, opts = {}, required_scopes = "", is_retry = false)
      ssl_options = {
        :ca_file => @config.ssl_ca_file,
        :verify => @config.ssl_verify,
        :verify_mode => @config.ssl_verify_mode,
        :client_cert => @config.ssl_client_cert,
        :client_key => @config.ssl_client_key
      }

      connection = Faraday.new(:url => config.base_url, :ssl => ssl_options) do |conn|
        @config.configure_middleware(conn)
        if opts[:header_params]["Content-Type"] == "multipart/form-data"
          conn.request :multipart
          conn.request :url_encoded
        end
        conn.adapter(Faraday.default_adapter)
      end

      begin
        response = connection.public_send(http_method.to_sym.downcase) do |req|
          build_request(http_method, path, req, opts)
        end

        if @config.debugging
          @config.logger.debug "HTTP response body ~BEGIN~\n#{response.body}\n~END~\n"
        end

        unless response.success?
          if (response.status == 401 || response.status == 403) && !is_retry && @config.client_id.length != 0 && @config.client_secret.length != 0
            authorization_header = opts[:header_params]["Authorization"]
            values = authorization_header.split(" ")
            if !values.nil? && values.length == 2
              update_oauth_access_token(required_scopes, values[1])
              call_api(http_method, path, opts, required_scopes, true)
            end

          elsif response.status == 0
            # Errors from libcurl will be made visible here
            fail ApiError.new(:code => 0,
                              :message => response.return_message)
          else
            fail ApiError.new(:code => response.status,
                              :response_headers => response.headers,
                              :response_body => response.body),
                 response.reason_phrase
          end
        end
      rescue Faraday::TimeoutError
        fail ApiError.new('Connection timed out')
      end

      return AvalaraSdk::ResponseHash.new(response.body, response.headers, response.status)
    end

    # Builds the HTTP request
    #
    # @param [String] http_method HTTP method/verb (e.g. POST)
    # @param [String] path URL path (e.g. /account/new)
    # @option opts [Hash] :header_params Header parameters
    # @option opts [Hash] :query_params Query parameters
    # @option opts [Hash] :form_params Query parameters
    # @option opts [Object] :body HTTP body (JSON/XML)
    # @return [Faraday::Request] A Faraday Request
    def build_request(http_method, path, request, opts = {})
      url = build_request_url(path, opts)
      http_method = http_method.to_sym.downcase

      header_params = @default_headers.merge(opts[:header_params] || {})
      header_params['X-Avalara-Client']="#{@config.app_name};#{@config.app_version};RubySdk;#{@sdk_version};#{@config.machine_name}"
      query_params = opts[:query_params] || {}
      form_params = opts[:form_params] || {}

      req_opts = {
        :params_encoding => @config.params_encoding,
        :timeout => @config.timeout,
        :verbose => @config.debugging
      }

      if [:post, :patch, :put, :delete].include?(http_method)
        req_body = build_request_body(header_params, form_params, opts[:body])
        if @config.debugging
          @config.logger.debug "HTTP request body param ~BEGIN~\n#{req_body}\n~END~\n"
        end
      end
      request.headers = header_params
      request.body = req_body
      request.options = OpenStruct.new(req_opts)
      request.url url
      request.params = query_params
      download_file(request) if opts[:return_type] == 'File'
      request
    end

    # Builds the HTTP request body
    #
    # @param [Hash] header_params Header parameters
    # @param [Hash] form_params Query parameters
    # @param [Object] body HTTP body (JSON/XML)
    # @return [String] HTTP body data in the form of string
    def build_request_body(header_params, form_params, body)
      # http form
      if header_params['Content-Type'] == 'application/x-www-form-urlencoded'
        data = URI.encode_www_form(form_params)
      elsif header_params['Content-Type'] == 'multipart/form-data'
        data = {}
        form_params.each do |key, value|
          case value
          when ::File, ::Tempfile
            # TODO hardcode to application/octet-stream, need better way to detect content type
            data[key] = Faraday::UploadIO.new(value.path, 'application/octet-stream', value.path)
          when ::Array, nil
            # let Faraday handle Array and nil parameters
            data[key] = value
          else
            data[key] = value.to_s
          end
        end
      elsif body
        data = body.is_a?(String) ? body : body.to_json
      else
        data = nil
      end
      data
    end

    def download_file(request)
      @stream = []

      # handle streaming Responses
      request.options.on_data = Proc.new do |chunk, overall_received_bytes|
        @stream << chunk
      end
    end

    # Check if the given MIME is a JSON MIME.
    # JSON MIME examples:
    #   application/json
    #   application/json; charset=UTF8
    #   APPLICATION/JSON
    #   */*
    # @param [String] mime MIME
    # @return [Boolean] True if the MIME is application/json
    def json_mime?(mime)
      (mime == '*/*') || !(mime =~ /Application\/.*json(?!p)(;.*)?/i).nil?
    end

    # Sanitize filename by removing path.
    # e.g. ../../sun.gif becomes sun.gif
    #
    # @param [String] filename the filename to be sanitized
    # @return [String] the sanitized filename
    def sanitize_filename(filename)
      filename.gsub(/.*[\/\\]/, '')
    end

    def build_request_url(path, opts = {})
      # Add leading and trailing slashes to path
      path = "/#{path}".gsub(/\/+/, '/')
      @config.base_url() + path      
    end

    # Sets user agent in HTTP header
    #
    # @param [String] user_agent User agent (e.g. openapi-generator/ruby/1.0.0)
    def user_agent=(user_agent)
      @user_agent = user_agent
      @default_headers['User-Agent'] = @user_agent
    end

    # Return Accept header based on an array of accepts provided.
    # @param [Array] accepts array for Accept
    # @return [String] the Accept header (e.g. application/json)
    def select_header_accept(accepts)
      return nil if accepts.nil? || accepts.empty?
      # use JSON when present, otherwise use all of the provided
      json_accept = accepts.find { |s| json_mime?(s) }
      json_accept || accepts.join(',')
    end

    # Return Content-Type header based on an array of content types provided.
    # @param [Array] content_types array for Content-Type
    # @return [String] the Content-Type header  (e.g. application/json)
    def select_header_content_type(content_types)
      # return nil by default
      return if content_types.nil? || content_types.empty?
      # use JSON when present, otherwise use the first one
      json_content_type = content_types.find { |s| json_mime?(s) }
      json_content_type || content_types.first
    end

    # Convert object (array, hash, object, etc) to JSON string.
    # @param [Object] model object to be converted into JSON string
    # @return [String] JSON string representation of the object
    def object_to_http_body(model)
      return model if model.nil? || model.is_a?(String)
      local_body = nil
      if model.is_a?(Array)
        local_body = model.map { |m| object_to_hash(m) }
      else
        local_body = object_to_hash(model)
      end
      local_body.to_json
    end

    # Convert object(non-array) to hash.
    # @param [Object] obj object to be converted into JSON string
    # @return [String] JSON string representation of the object
    def object_to_hash(obj)
      if obj.respond_to?(:to_hash)
        obj.to_hash
      else
        obj
      end
    end

    # Build parameter value according to the given collection format.
    # @param [String] collection_format one of :csv, :ssv, :tsv, :pipes and :multi
    def build_collection_param(param, collection_format)
      case collection_format
      when :csv
        param.join(',')
      when :ssv
        param.join(' ')
      when :tsv
        param.join("\t")
      when :pipes
        param.join('|')
      when :multi
        # return the array directly as typhoeus will handle it as expected
        param
      else
        fail "unknown collection format: #{collection_format.inspect}"
      end
    end

    def apply_auth_to_request!(header_params, auth_names, required_scopes)
      if !@config.bearer_token.nil? && @config.bearer_token.length != 0
        header_params['Authorization'] = "Bearer #{@config.bearer_token}"
      elsif auth_names.include?("OAuth") && !@config.client_id.nil? && !@config.client_secret.nil? && @config.client_id.length != 0 && @config.client_secret.length != 0
        scopes = standardize_scopes required_scopes
        access_token = get_oauth_access_token scopes
        if access_token.nil?
          update_oauth_access_token required_scopes, nil
          access_token = get_oauth_access_token required_scopes
        end
        header_params['Authorization'] = "Bearer #{access_token}"
      elsif !@config.username.nil? && !@config.password.nil? && @config.username.length != 0  && @config.password.length != 0
        header_params['Authorization'] = create_basic_auth_header @config.username, @config.password
      end

    end

    def get_oauth_access_token(required_scopes)
      token_metadata = @access_token_map[required_scopes]
      if !token_metadata.nil?
        expiration_time = Time.now + 300
        if expiration_time < token_metadata.expiry
          return token_metadata.access_token
        end
      end
      return nil
    end

    def update_oauth_access_token(required_scopes, access_token)
      current_access_token = get_oauth_access_token required_scopes
      if current_access_token.nil? || current_access_token == access_token
        begin
          data = build_oauth_request required_scopes
          timestamp = Time.now + data['expires_in'].to_i
          @access_token_map[required_scopes] = AvalaraSdk::TokenMetadata.new(data['access_token'], timestamp)
        rescue Exception => e
          puts "OAuth2 Token retrieval failed. Error: #{e.message}"
          raise "OAuth2 Token retrieval failed. Error: #{e.message}"
        end
      end
    end

    def build_oauth_request(required_scopes)
      populate_token_url openid_connect_url
      authorization_value = create_basic_auth_header @config.client_id, @config.client_secret
      data = { "grant_type"=>"client_credentials", "scope"=>"#{required_scopes}" }

      response = Faraday.post(@token_url) do |req|
        req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req.headers['Authorization'] = authorization_value
        req.headers['Accept'] = 'application/json'
        req.body = URI.encode_www_form(data)
      end
      JSON.parse(response.body)
    end

    def create_basic_auth_header(username, password)
      "Basic #{Base64.encode64("#{username}:#{password}")}"
    end

    def populate_token_url(openid_connect_url)
      if @config.environment.downcase == 'test'
        @token_url = @config.test_token_url
      elsif @token_url.nil? || @token_url.length == 0
        begin
          token_response = get_token_url openid_connect_url
          @token_url = token_response['token_endpoint']
        rescue Exception => e
          puts "Exception when calling OpenIdConnect to fetch the token endpoint. Error: #{e.message}"
          raise "Exception when calling OpenIdConnect to fetch the token endpoint. Error: #{e.message}"
        end
      end
    end

    def get_token_url(openid_connect_url)
      response = Faraday.get(openid_connect_url) do |req|
        req.headers['Accept'] = 'application/json'
      end
      JSON.parse(response.body)
    end

    def standardize_scopes(required_scopes)
      scopes = required_scopes.split(" ")
      scopes.sort
      scopes.join(" ")
    end

    def openid_connect_url
      case @config.environment.downcase
      when 'sandbox'
        SANDBOX_OPENID_CONFIG_URL
      when 'production'
        PRODUCTION_OPENID_CONFIG_URL
      when 'qa'
        QA_OPENID_CONFIG_URL
      end
    end
  end
end
