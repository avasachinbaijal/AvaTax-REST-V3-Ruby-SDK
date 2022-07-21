=begin
#foundation

#Platform foundation consists of services on top of which the Avalara Compliance Cloud platform is built. These services are foundational and provide functionality such as common organization, tenant and user management for the rest of the compliance platform.

SDK Version : 2.4.41


=end

require 'cgi'

module AvalaraSdk::IAMDS
  class ResourceApi
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
  
    # Create a resource.
    # The response contains the same object as posted and fills in the newly assigned resource ID.
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [Resource] :resource 
    # @return [Resource]
    def create_resource(opts = {})
      data, _status_code, _headers = create_resource_with_http_info(opts)
      data
    end

    # Create a resource.
    # The response contains the same object as posted and fills in the newly assigned resource ID.
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [Resource] :resource 
    # @return [Array<(Resource, Integer, Hash)>] Resource data, response status code and response headers
    def create_resource_with_http_info(opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.create_resource ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources'

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
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'resource'])

      # return_type
      return_type = opts[:debug_return_type] || 'Resource'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.create_resource",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:POST, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#create_resource\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Delete a resource.
    # Deletes the resource by ID.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [nil]
    def delete_resource(resource_id, opts = {})
      delete_resource_with_http_info(resource_id, opts)
      nil
    end

    # Delete a resource.
    # Deletes the resource by ID.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def delete_resource_with_http_info(resource_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.delete_resource ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'resource_id' is set
      if @api_client.config.client_side_validation && resource_id.nil?
        fail ArgumentError, "Missing the required parameter 'resource_id' when calling ResourceApi.delete_resource"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources/{resource-id}'.sub('{' + 'resource-id' + '}', CGI.escape(resource_id.to_s))

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
        :operation => :"ResourceApi.delete_resource",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#delete_resource\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Retrieve a resource.
    # Retrieves the specified resource.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_none_match Only return the resource if the ETag is different from the ETag passed in.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @return [Resource]
    def get_resource(resource_id, opts = {})
      data, _status_code, _headers = get_resource_with_http_info(resource_id, opts)
      data
    end

    # Retrieve a resource.
    # Retrieves the specified resource.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_none_match Only return the resource if the ETag is different from the ETag passed in.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @return [Array<(Resource, Integer, Hash)>] Resource data, response status code and response headers
    def get_resource_with_http_info(resource_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.get_resource ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'resource_id' is set
      if @api_client.config.client_side_validation && resource_id.nil?
        fail ArgumentError, "Missing the required parameter 'resource_id' when calling ResourceApi.get_resource"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources/{resource-id}'.sub('{' + 'resource-id' + '}', CGI.escape(resource_id.to_s))

      # query parameters
      query_params = opts[:query_params] || {}

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json', 'text/plain'])
      header_params[:'avalara-version'] = opts[:'avalara_version'] if !opts[:'avalara_version'].nil?
      header_params[:'X-Correlation-Id'] = opts[:'x_correlation_id'] if !opts[:'x_correlation_id'].nil?
      header_params[:'If-None-Match'] = opts[:'if_none_match'] if !opts[:'if_none_match'].nil?
      header_params[:'If-Match'] = opts[:'if_match'] if !opts[:'if_match'].nil?

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'Resource'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.get_resource",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#get_resource\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get a list of all permissions on a resource.
    # Retrieve a list of all permissions a resource belongs to which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * name
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [PermissionList]
    def list_resource_permissions(resource_id, opts = {})
      data, _status_code, _headers = list_resource_permissions_with_http_info(resource_id, opts)
      data
    end

    # Get a list of all permissions on a resource.
    # Retrieve a list of all permissions a resource belongs to which the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties:  * name
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(PermissionList, Integer, Hash)>] PermissionList data, response status code and response headers
    def list_resource_permissions_with_http_info(resource_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.list_resource_permissions ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'resource_id' is set
      if @api_client.config.client_side_validation && resource_id.nil?
        fail ArgumentError, "Missing the required parameter 'resource_id' when calling ResourceApi.list_resource_permissions"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources/{resource-id}/permissions'.sub('{' + 'resource-id' + '}', CGI.escape(resource_id.to_s))

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
      return_type = opts[:debug_return_type] || 'PermissionList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.list_resource_permissions",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#list_resource_permissions\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Get all resources which the user has access to.
    # Retrieve a list of all resources the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties: * displayName * namespace * system/identifier
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [ResourceList]
    def list_resources(opts = {})
      data, _status_code, _headers = list_resources_with_http_info(opts)
      data
    end

    # Get all resources which the user has access to.
    # Retrieve a list of all resources the authenticated user has access to. This list is paged, returning no more than 1000 items at a time.  Filterable properties: * displayName * namespace * system/identifier
    # @param [Hash] opts the optional parameters
    # @option opts [String] :filter A filter statement to identify specific records to retrieve.
    # @option opts [String] :top If nonzero, return no more than this number of results.  Used with &#x60;$skip&#x60; to provide pagination for large datasets.  Unless otherwise specified, the maximum number of records that can be returned from an API call is 1,000 records.
    # @option opts [String] :skip If nonzero, skip this number of results before returning data.  Used with &#x60;$top&#x60; to provide pagination for large datasets.
    # @option opts [String] :order_by A comma separated list of sort statements in the format &#x60;(fieldname) [ASC|DESC]&#x60;, for example &#x60;id ASC&#x60;.
    # @option opts [Boolean] :count If set to &#39;true&#39;, requests the count of items as part of the response. Default: &#39;false&#39;. If the value cannot be
    # @option opts [Boolean] :count_only If set to &#39;true&#39;, requests the count of items as part of the response. No values are returned. Default: &#39;false&#39;.
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @return [Array<(ResourceList, Integer, Hash)>] ResourceList data, response status code and response headers
    def list_resources_with_http_info(opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.list_resources ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources'

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
      return_type = opts[:debug_return_type] || 'ResourceList'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.list_resources",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#list_resources\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Update the passed in fields from the message on the resource.
    # Updates only the fields passed in for the specified resource.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Resource] :resource 
    # @return [nil]
    def patch_resource(resource_id, opts = {})
      patch_resource_with_http_info(resource_id, opts)
      nil
    end

    # Update the passed in fields from the message on the resource.
    # Updates only the fields passed in for the specified resource.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Resource] :resource 
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def patch_resource_with_http_info(resource_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.patch_resource ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'resource_id' is set
      if @api_client.config.client_side_validation && resource_id.nil?
        fail ArgumentError, "Missing the required parameter 'resource_id' when calling ResourceApi.patch_resource"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources/{resource-id}'.sub('{' + 'resource-id' + '}', CGI.escape(resource_id.to_s))

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
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'resource'])

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.patch_resource",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PATCH, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#patch_resource\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Update all fields on a resource.
    # Replaces the specified resource with the resource in the body.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Resource] :resource 
    # @return [nil]
    def replace_resource(resource_id, opts = {})
      replace_resource_with_http_info(resource_id, opts)
      nil
    end

    # Update all fields on a resource.
    # Replaces the specified resource with the resource in the body.
    # @param resource_id [String] 
    # @param [Hash] opts the optional parameters
    # @option opts [String] :avalara_version States the version of the API to use.
    # @option opts [String] :x_correlation_id Correlation ID to pass into the method. Returned in any response.
    # @option opts [String] :if_match Only execute the operation if the ETag for the current version of the resource matches the ETag in this header.
    # @option opts [Resource] :resource 
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def replace_resource_with_http_info(resource_id, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ResourceApi.replace_resource ...'
      end
      # OAuth2 Scopes
      required_scopes = 'iam avatax_api'
      # verify the required parameter 'resource_id' is set
      if @api_client.config.client_side_validation && resource_id.nil?
        fail ArgumentError, "Missing the required parameter 'resource_id' when calling ResourceApi.replace_resource"
      end
      allowable_values = ["1.0.0"]
      if @api_client.config.client_side_validation && opts[:'avalara_version'] && !allowable_values.include?(opts[:'avalara_version'])
        fail ArgumentError, "invalid value for \"avalara_version\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/resources/{resource-id}'.sub('{' + 'resource-id' + '}', CGI.escape(resource_id.to_s))

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
      post_body = opts[:debug_body] || @api_client.object_to_http_body(opts[:'resource'])

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['OAuth']

      @api_client.apply_auth_to_request!(header_params, auth_names, required_scopes)

      new_options = opts.merge(
        :operation => :"ResourceApi.replace_resource",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ResourceApi#replace_resource\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
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
