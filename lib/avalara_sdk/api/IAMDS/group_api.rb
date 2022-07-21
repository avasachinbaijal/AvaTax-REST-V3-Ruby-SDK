=begin
#foundation

#Platform foundation consists of services on top of which the Avalara Compliance Cloud platform is built. These services are foundational and provide functionality such as common organization, tenant and user management for the rest of the compliance platform.

SDK Version : 2.4.41


=end

require 'cgi'

module AvalaraSdk::IAMDS
  class GroupApi
    attr_accessor :api_client

    def initialize(api_client)
      if (api_client.nil?)
        fail  ArgumentError,'api_client is nil'
      end
      api_client.set_sdk_version("2.4.41")
      @api_client = api_client
    end

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

    # Deserialize the response to the given return type.
    #
    # @param [Response] response HTTP response
    # @param [String] return_type some examples: "User", "Array<User>", "Hash<String, Integer>"
    def deserialize(response, return_type)
      body = response.body

      # handle file downloading - return the File instance processed in request callbacks
      # note that response body is empty when the file is written in chunks in request on_body callback
      return @tempfile if return_type == 'File'

      return nil if body.nil? || body.empty?

      # return response body directly for String return type
      return body if return_type == 'String'

      # ensuring a default content type
      content_type = response.headers['Content-Type'] || 'application/json'

      fail "Content-Type is not supported: #{content_type}" unless json_mime?(content_type)

      begin
        data = JSON.parse("[#{body}]", :symbolize_names => true)[0]
      rescue JSON::ParserError => e
        if %w(String Date Time).include?(return_type)
          data = body
        else
          raise e
        end
      end

      convert_to_type data, return_type
    end

    # Convert data to the given return type.
    # @param [Object] data Data to be converted
    # @param [String] return_type Return type
    # @return [Mixed] Data in a particular type
    def convert_to_type(data, return_type)
      return nil if data.nil?
      case return_type
      when 'String'
        data.to_s
      when 'Integer'
        data.to_i
      when 'Float'
        data.to_f
      when 'Boolean'
        data == true
      when 'Time'
        # parse date time (expecting ISO 8601 format)
        Time.parse data
      when 'Date'
        # parse date time (expecting ISO 8601 format)
        Date.parse data
      when 'Object'
        # generic object (usually a Hash), return directly
        data
      when /\AArray<(.+)>\z/
        # e.g. Array<Pet>
        sub_type = $1
        data.map { |item| convert_to_type(item, sub_type) }
      when /\AHash\<String, (.+)\>\z/
        # e.g. Hash<String, Integer>
        sub_type = $1
        {}.tap do |hash|
          data.each { |k, v| hash[k] = convert_to_type(v, sub_type) }
        end
      else
        # models (e.g. Pet) or oneOf
        klass = AvalaraSdk::IAMDS.const_get(return_type)
        klass.respond_to?(:openapi_one_of) ? klass.build(data) : klass.build_from_hash(data)
      end
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
      @config.base_url(opts[:operation]) + path
    end

    # Update header and query params based on authentication settings.
    #
    # @param [Hash] header_params Header parameters
    # @param [Hash] query_params Query parameters
    # @param [String] auth_names Authentication scheme name
    def update_params_for_auth!(header_params, query_params, auth_names)
      Array(auth_names).each do |auth_name|
        auth_setting = @config.auth_settings[auth_name]
        next unless auth_setting
        case auth_setting[:in]
        when 'header' then header_params[auth_setting[:key]] = auth_setting[:value]
        when 'query'  then query_params[auth_setting[:key]] = auth_setting[:value]
        else fail ArgumentError, 'Authentication token must be in `query` or `header`'
        end
      end
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
  
    # Add a device to a group.
    # Adds a device to a group.
    # @param group_id [String] 
    # @param device_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def add_device_to_group(group_id, device_id, opts = {})
      add_device_to_group_with_http_info(group_id, device_id, opts)
      nil
    end

    # Add a device to a group.
    # Adds a device to a group.
    # @param group_id [String] 
    # @param device_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def add_device_to_group_with_http_info(group_id, device_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.add_device_to_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.add_device_to_group"
      end
      # verify the required parameter 'device_id' is set
      if @api_client.config.client_side_validation && device_id.nil?
        fail ArgumentError, "Missing the required parameter 'device_id' when calling GroupApi.add_device_to_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/devices/{device-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'device-id' + '}', CGI.escape(device_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.add_device_to_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#add_device_to_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Add a grant to a group.
    # Adds a grant to a group.
    # @param group_id [String] 
    # @param grant_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def add_grant_to_group(group_id, grant_id, opts = {})
      add_grant_to_group_with_http_info(group_id, grant_id, opts)
      nil
    end

    # Add a grant to a group.
    # Adds a grant to a group.
    # @param group_id [String] 
    # @param grant_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def add_grant_to_group_with_http_info(group_id, grant_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.add_grant_to_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.add_grant_to_group"
      end
      # verify the required parameter 'grant_id' is set
      if @api_client.config.client_side_validation && grant_id.nil?
        fail ArgumentError, "Missing the required parameter 'grant_id' when calling GroupApi.add_grant_to_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/grants/{grant-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'grant-id' + '}', CGI.escape(grant_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.add_grant_to_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#add_grant_to_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Add a user to a group.
    # Adds a user to a group.
    # @param group_id [String] 
    # @param user_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def add_user_to_group(group_id, user_id, opts = {})
      add_user_to_group_with_http_info(group_id, user_id, opts)
      nil
    end

    # Add a user to a group.
    # Adds a user to a group.
    # @param group_id [String] 
    # @param user_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def add_user_to_group_with_http_info(group_id, user_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.add_user_to_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.add_user_to_group"
      end
      # verify the required parameter 'user_id' is set
      if @api_client.config.client_side_validation && user_id.nil?
        fail ArgumentError, "Missing the required parameter 'user_id' when calling GroupApi.add_user_to_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/users/{user-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'user-id' + '}', CGI.escape(user_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.add_user_to_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#add_user_to_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Create a group.
    # On a post, the group ID will not be known since it is assigned by the system. The response contains the group, including ID.
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [Group] :group 
    # @return [Group]
    def create_group(opts = {})
      data, _status_code, _headers = create_group_with_http_info(opts)
      data
    end

    # Create a group.
    # On a post, the group ID will not be known since it is assigned by the system. The response contains the group, including ID.
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [Group] :group 
    # @return [Array<(Group, Integer, Hash)>] Group data, response status code and response headers
    def create_group_with_http_info(opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.create_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups'

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      # HTTP header 'Content-Type'
      content_type = @api_client.select_header_content_type(['application/json'])
      if !content_type.nil?
          header_params['Content-Type'] = content_type
      end
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'group'])

      # return_type
      return_type = opts[:debug_return_type] || 'Group'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.create_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:POST, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#create_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Delete a group.
    # Deletes the specified group.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @return [nil]
    def delete_group(group_id, opts = {})
      delete_group_with_http_info(group_id, opts)
      nil
    end

    # Delete a group.
    # Deletes the specified group.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def delete_group_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.delete_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.delete_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?
      header_params[:'If-Match'] = opts[:'if_match'] if !opts[:'if_match'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.delete_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#delete_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get a group by ID.
    # Retrieves the specified group.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_none_match Only return the resource if the ETag is different from the ETag passed in.
    # @return [Group]
    def get_group(group_id, opts = {})
      data, _status_code, _headers = get_group_with_http_info(group_id, opts)
      data
    end

    # Get a group by ID.
    # Retrieves the specified group.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_none_match Only return the resource if the ETag is different from the ETag passed in.
    # @return [Array<(Group, Integer, Hash)>] Group data, response status code and response headers
    def get_group_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.get_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.get_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?
      header_params[:'If-None-Match'] = opts[:'if_none_match'] if !opts[:'if_none_match'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'Group'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.get_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#get_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get all devices in a group.
    # Retrieve a list of all devices within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * tenant/identifier * active * grants/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [DeviceList]
    def list_group_devices(group_id, opts = {})
      data, _status_code, _headers = list_group_devices_with_http_info(group_id, opts)
      data
    end

    # Get all devices in a group.
    # Retrieve a list of all devices within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * tenant/identifier * active * grants/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(DeviceList, Integer, Hash)>] DeviceList data, response status code and response headers
    def list_group_devices_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.list_group_devices ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.list_group_devices"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/devices'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'$filter'] = opts[:'filter'] if !opts[:'filter'].nil?
      query_params[:'$top'] = opts[:'top'] if !opts[:'top'].nil?
      query_params[:'$skip'] = opts[:'skip'] if !opts[:'skip'].nil?
      query_params[:'$orderBy'] = opts[:'order_by'] if !opts[:'order_by'].nil?
      query_params[:'count'] = opts[:'count'] if !opts[:'count'].nil?
      query_params[:'countOnly'] = opts[:'count_only'] if !opts[:'count_only'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'DeviceList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.list_group_devices",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#list_group_devices\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get all grants in a group.
    # Retrieve a list of all grants within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * system/identifier * type * role/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [GrantList]
    def list_group_grants(group_id, opts = {})
      data, _status_code, _headers = list_group_grants_with_http_info(group_id, opts)
      data
    end

    # Get all grants in a group.
    # Retrieve a list of all grants within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * system/identifier * type * role/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(GrantList, Integer, Hash)>] GrantList data, response status code and response headers
    def list_group_grants_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.list_group_grants ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.list_group_grants"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/grants'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'$filter'] = opts[:'filter'] if !opts[:'filter'].nil?
      query_params[:'$top'] = opts[:'top'] if !opts[:'top'].nil?
      query_params[:'$skip'] = opts[:'skip'] if !opts[:'skip'].nil?
      query_params[:'$orderBy'] = opts[:'order_by'] if !opts[:'order_by'].nil?
      query_params[:'count'] = opts[:'count'] if !opts[:'count'].nil?
      query_params[:'countOnly'] = opts[:'count_only'] if !opts[:'count_only'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'GrantList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.list_group_grants",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#list_group_grants\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get all users in a group.
    # Retrieve a list of all users within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * emails/value * active * userName * grants/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [UserList]
    def list_group_users(group_id, opts = {})
      data, _status_code, _headers = list_group_users_with_http_info(group_id, opts)
      data
    end

    # Get all users in a group.
    # Retrieve a list of all users within a group which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * displayName * emails/value * active * userName * grants/identifier
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(UserList, Integer, Hash)>] UserList data, response status code and response headers
    def list_group_users_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.list_group_users ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.list_group_users"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/users'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'$filter'] = opts[:'filter'] if !opts[:'filter'].nil?
      query_params[:'$top'] = opts[:'top'] if !opts[:'top'].nil?
      query_params[:'$skip'] = opts[:'skip'] if !opts[:'skip'].nil?
      query_params[:'$orderBy'] = opts[:'order_by'] if !opts[:'order_by'].nil?
      query_params[:'count'] = opts[:'count'] if !opts[:'count'].nil?
      query_params[:'countOnly'] = opts[:'count_only'] if !opts[:'count_only'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'UserList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.list_group_users",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#list_group_users\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get all groups.
    # Retrieve a list of all groups the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:   * displayName * tenants/identifier * grants/identifier
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [GroupList]
    def list_groups(opts = {})
      data, _status_code, _headers = list_groups_with_http_info(opts)
      data
    end

    # Get all groups.
    # Retrieve a list of all groups the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:   * displayName * tenants/identifier * grants/identifier
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(GroupList, Integer, Hash)>] GroupList data, response status code and response headers
    def list_groups_with_http_info(opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.list_groups ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups'

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'$filter'] = opts[:'filter'] if !opts[:'filter'].nil?
      query_params[:'$top'] = opts[:'top'] if !opts[:'top'].nil?
      query_params[:'$skip'] = opts[:'skip'] if !opts[:'skip'].nil?
      query_params[:'count'] = opts[:'count'] if !opts[:'count'].nil?
      query_params[:'countOnly'] = opts[:'count_only'] if !opts[:'count_only'].nil?
      query_params[:'$orderBy'] = opts[:'order_by'] if !opts[:'order_by'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'GroupList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.list_groups",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#list_groups\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Update the fields in the message body on the group.
    # Updates the fields on a group which should change.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Group] :group 
    # @return [nil]
    def patch_group(group_id, opts = {})
      patch_group_with_http_info(group_id, opts)
      nil
    end

    # Update the fields in the message body on the group.
    # Updates the fields on a group which should change.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Group] :group 
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def patch_group_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.patch_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.patch_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      # HTTP header 'Content-Type'
      content_type = @api_client.select_header_content_type(['application/json'])
      if !content_type.nil?
          header_params['Content-Type'] = content_type
      end
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?
      header_params[:'If-Match'] = opts[:'if_match'] if !opts[:'if_match'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'group'])

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.patch_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PATCH, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#patch_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Remove a device from a group.
    # Removes a device from a group.
    # @param group_id [String] 
    # @param device_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def remove_device_from_group(group_id, device_id, opts = {})
      remove_device_from_group_with_http_info(group_id, device_id, opts)
      nil
    end

    # Remove a device from a group.
    # Removes a device from a group.
    # @param group_id [String] 
    # @param device_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def remove_device_from_group_with_http_info(group_id, device_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.remove_device_from_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.remove_device_from_group"
      end
      # verify the required parameter 'device_id' is set
      if @api_client.config.client_side_validation && device_id.nil?
        fail ArgumentError, "Missing the required parameter 'device_id' when calling GroupApi.remove_device_from_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/devices/{device-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'device-id' + '}', CGI.escape(device_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.remove_device_from_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#remove_device_from_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Delete a grant from a group.
    # Removes a grant from a group.
    # @param group_id [String] 
    # @param grant_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def remove_grant_from_group(group_id, grant_id, opts = {})
      remove_grant_from_group_with_http_info(group_id, grant_id, opts)
      nil
    end

    # Delete a grant from a group.
    # Removes a grant from a group.
    # @param group_id [String] 
    # @param grant_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def remove_grant_from_group_with_http_info(group_id, grant_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.remove_grant_from_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.remove_grant_from_group"
      end
      # verify the required parameter 'grant_id' is set
      if @api_client.config.client_side_validation && grant_id.nil?
        fail ArgumentError, "Missing the required parameter 'grant_id' when calling GroupApi.remove_grant_from_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/grants/{grant-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'grant-id' + '}', CGI.escape(grant_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.remove_grant_from_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#remove_grant_from_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Delete a user from a group.
    # Removes a user from a group.
    # @param group_id [String] 
    # @param user_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def remove_user_from_group(group_id, user_id, opts = {})
      remove_user_from_group_with_http_info(group_id, user_id, opts)
      nil
    end

    # Delete a user from a group.
    # Removes a user from a group.
    # @param group_id [String] 
    # @param user_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def remove_user_from_group_with_http_info(group_id, user_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.remove_user_from_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.remove_user_from_group"
      end
      # verify the required parameter 'user_id' is set
      if @api_client.config.client_side_validation && user_id.nil?
        fail ArgumentError, "Missing the required parameter 'user_id' when calling GroupApi.remove_user_from_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}/users/{user-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s)).sub('{' + 'user-id' + '}', CGI.escape(user_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.remove_user_from_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#remove_user_from_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Update all fields on a group.
    # Updates the group with the data in the request body.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Group] :group 
    # @return [nil]
    def replace_group(group_id, opts = {})
      replace_group_with_http_info(group_id, opts)
      nil
    end

    # Update all fields on a group.
    # Updates the group with the data in the request body.
    # @param group_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Group] :group 
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def replace_group_with_http_info(group_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: GroupApi.replace_group ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'group_id' is set
      if @api_client.config.client_side_validation && group_id.nil?
        fail ArgumentError, "Missing the required parameter 'group_id' when calling GroupApi.replace_group"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/groups/{group-id}'.sub('{' + 'group-id' + '}', CGI.escape(group_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['text/plain'])
      # HTTP header 'Content-Type'
      content_type = @api_client.select_header_content_type(['application/json'])
      if !content_type.nil?
          header_params['Content-Type'] = content_type
      end
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?
      header_params[:'If-Match'] = opts[:'if_match'] if !opts[:'if_match'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'group'])

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"GroupApi.replace_group",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: GroupApi#replace_group\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end
  end
end
