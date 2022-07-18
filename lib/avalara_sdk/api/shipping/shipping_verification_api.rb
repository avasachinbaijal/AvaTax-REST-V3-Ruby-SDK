=begin
#Avalara Shipping Verification for Beverage Alcohol

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.4.41


=end

require 'cgi'

module AvalaraSdk::Shipping
  class ShippingVerificationApi
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
        klass = AvalaraSdk::Shipping.const_get(return_type)
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
  
    # Removes the transaction from consideration when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [nil]
    def deregister_shipment(company_code, transaction_code, opts = {})
      deregister_shipment_with_http_info(company_code, transaction_code, opts)
      nil
    end

    # Removes the transaction from consideration when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def deregister_shipment_with_http_info(company_code, transaction_code, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ShippingVerificationApi.deregister_shipment ...'
      end
      # verify the required parameter 'company_code' is set
      if @api_client.config.client_side_validation && company_code.nil?
        fail ArgumentError, "Missing the required parameter 'company_code' when calling ShippingVerificationApi.deregister_shipment"
      end
      # verify the required parameter 'transaction_code' is set
      if @api_client.config.client_side_validation && transaction_code.nil?
        fail ArgumentError, "Missing the required parameter 'transaction_code' when calling ShippingVerificationApi.deregister_shipment"
      end
      allowable_values = ["SalesInvoice", "ReturnInvoice"]
      if @api_client.config.client_side_validation && opts[:'document_type'] && !allowable_values.include?(opts[:'document_type'])
        fail ArgumentError, "invalid value for \"document_type\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration'.sub('{' + 'companyCode' + '}', CGI.escape(company_code.to_s)).sub('{' + 'transactionCode' + '}', CGI.escape(transaction_code.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'documentType'] = opts[:'document_type'] if !opts[:'document_type'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json'])

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['BasicAuth', 'Bearer']

      new_options = opts.merge(
        :operation => :"ShippingVerificationApi.deregister_shipment",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#deregister_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [nil]
    def register_shipment(company_code, transaction_code, opts = {})
      register_shipment_with_http_info(company_code, transaction_code, opts)
      nil
    end

    # Registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [Array<(nil, Integer, Hash)>] nil, response status code and response headers
    def register_shipment_with_http_info(company_code, transaction_code, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ShippingVerificationApi.register_shipment ...'
      end
      # verify the required parameter 'company_code' is set
      if @api_client.config.client_side_validation && company_code.nil?
        fail ArgumentError, "Missing the required parameter 'company_code' when calling ShippingVerificationApi.register_shipment"
      end
      # verify the required parameter 'transaction_code' is set
      if @api_client.config.client_side_validation && transaction_code.nil?
        fail ArgumentError, "Missing the required parameter 'transaction_code' when calling ShippingVerificationApi.register_shipment"
      end
      allowable_values = ["SalesInvoice", "ReturnInvoice"]
      if @api_client.config.client_side_validation && opts[:'document_type'] && !allowable_values.include?(opts[:'document_type'])
        fail ArgumentError, "invalid value for \"document_type\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registration'.sub('{' + 'companyCode' + '}', CGI.escape(company_code.to_s)).sub('{' + 'transactionCode' + '}', CGI.escape(transaction_code.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'documentType'] = opts[:'document_type'] if !opts[:'document_type'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json'])

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type]

      # auth_names
      auth_names = opts[:debug_auth_names] || ['BasicAuth', 'Bearer']

      new_options = opts.merge(
        :operation => :"ShippingVerificationApi.register_shipment",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#register_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [ShippingVerifyResult]
    def register_shipment_if_compliant(company_code, transaction_code, opts = {})
      data, _status_code, _headers = register_shipment_if_compliant_with_http_info(company_code, transaction_code, opts)
      data
    end

    # Evaluates a transaction against a set of direct-to-consumer shipping regulations and, if compliant, registers the transaction so that it may be included when evaluating regulations that span multiple transactions.
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [Array<(ShippingVerifyResult, Integer, Hash)>] ShippingVerifyResult data, response status code and response headers
    def register_shipment_if_compliant_with_http_info(company_code, transaction_code, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ShippingVerificationApi.register_shipment_if_compliant ...'
      end
      # verify the required parameter 'company_code' is set
      if @api_client.config.client_side_validation && company_code.nil?
        fail ArgumentError, "Missing the required parameter 'company_code' when calling ShippingVerificationApi.register_shipment_if_compliant"
      end
      # verify the required parameter 'transaction_code' is set
      if @api_client.config.client_side_validation && transaction_code.nil?
        fail ArgumentError, "Missing the required parameter 'transaction_code' when calling ShippingVerificationApi.register_shipment_if_compliant"
      end
      allowable_values = ["SalesInvoice", "ReturnInvoice"]
      if @api_client.config.client_side_validation && opts[:'document_type'] && !allowable_values.include?(opts[:'document_type'])
        fail ArgumentError, "invalid value for \"document_type\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/registerIfCompliant'.sub('{' + 'companyCode' + '}', CGI.escape(company_code.to_s)).sub('{' + 'transactionCode' + '}', CGI.escape(transaction_code.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'documentType'] = opts[:'document_type'] if !opts[:'document_type'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json'])

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'ShippingVerifyResult'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['BasicAuth', 'Bearer']

      new_options = opts.merge(
        :operation => :"ShippingVerificationApi.register_shipment_if_compliant",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#register_shipment_if_compliant\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      if new_options[:return_type]
        data = deserialize(response, new_options[:return_type])
      else
        data = nil
      end
      return data, response.code, response.headers
    end

    # Evaluates a transaction against a set of direct-to-consumer shipping regulations.
    # The transaction and its lines must meet the following criteria in order to be evaluated: * The transaction must be recorded. Using a type of *SalesInvoice* is recommended. * A parameter with the name *AlcoholRouteType* must be specified and the value must be one of the following: '*DTC*', '*Retailer DTC*' * A parameter with the name *RecipientName* must be specified and the value must be the name of the recipient. * Each alcohol line must include a *ContainerSize* parameter that describes the volume of a single container. Use the *unit* field to specify one of the following units: '*Litre*', '*Millilitre*', '*gallon (US fluid)*', '*quart (US fluid)*', '*ounce (fluid US customary)*' * Each alcohol line must include a *PackSize* parameter that describes the number of containers in a pack. Specify *Count* in the *unit* field.  Optionally, the transaction and its lines may use the following parameters: * The *ShipDate* parameter may be used if the date of shipment is different than the date of the transaction. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *RecipientDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *PurchaserDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *SalesLocation* parameter may be used to describe whether the sale was made *OnSite* or *OffSite*. *OffSite* is the default value. * The *AlcoholContent* parameter may be used to describe the alcohol percentage by volume of the item. Specify *Percentage* in the *unit* field.  **Security Policies** This API depends on all of the following active subscriptions: *AvaAlcohol, AutoAddress, AvaTaxPro*
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [ShippingVerifyResult]
    def verify_shipment(company_code, transaction_code, opts = {})
      data, _status_code, _headers = verify_shipment_with_http_info(company_code, transaction_code, opts)
      data
    end

    # Evaluates a transaction against a set of direct-to-consumer shipping regulations.
    # The transaction and its lines must meet the following criteria in order to be evaluated: * The transaction must be recorded. Using a type of *SalesInvoice* is recommended. * A parameter with the name *AlcoholRouteType* must be specified and the value must be one of the following: &#39;*DTC*&#39;, &#39;*Retailer DTC*&#39; * A parameter with the name *RecipientName* must be specified and the value must be the name of the recipient. * Each alcohol line must include a *ContainerSize* parameter that describes the volume of a single container. Use the *unit* field to specify one of the following units: &#39;*Litre*&#39;, &#39;*Millilitre*&#39;, &#39;*gallon (US fluid)*&#39;, &#39;*quart (US fluid)*&#39;, &#39;*ounce (fluid US customary)*&#39; * Each alcohol line must include a *PackSize* parameter that describes the number of containers in a pack. Specify *Count* in the *unit* field.  Optionally, the transaction and its lines may use the following parameters: * The *ShipDate* parameter may be used if the date of shipment is different than the date of the transaction. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *RecipientDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *PurchaserDOB* parameter may be used to evaluate age restrictions. The value should be ISO-8601 compliant (e.g. 2020-07-21). * The *SalesLocation* parameter may be used to describe whether the sale was made *OnSite* or *OffSite*. *OffSite* is the default value. * The *AlcoholContent* parameter may be used to describe the alcohol percentage by volume of the item. Specify *Percentage* in the *unit* field.  **Security Policies** This API depends on all of the following active subscriptions: *AvaAlcohol, AutoAddress, AvaTaxPro*
    # @param company_code [String] The company code of the company that recorded the transaction
    # @param transaction_code [String] The transaction code to retrieve
    # @param [Hash] opts the optional parameters
    # @option opts [String] :document_type (Optional): The document type of the transaction to operate on. If omitted, defaults to \&quot;SalesInvoice\&quot;
    # @return [Array<(ShippingVerifyResult, Integer, Hash)>] ShippingVerifyResult data, response status code and response headers
    def verify_shipment_with_http_info(company_code, transaction_code, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: ShippingVerificationApi.verify_shipment ...'
      end
      # verify the required parameter 'company_code' is set
      if @api_client.config.client_side_validation && company_code.nil?
        fail ArgumentError, "Missing the required parameter 'company_code' when calling ShippingVerificationApi.verify_shipment"
      end
      # verify the required parameter 'transaction_code' is set
      if @api_client.config.client_side_validation && transaction_code.nil?
        fail ArgumentError, "Missing the required parameter 'transaction_code' when calling ShippingVerificationApi.verify_shipment"
      end
      allowable_values = ["SalesInvoice", "ReturnInvoice"]
      if @api_client.config.client_side_validation && opts[:'document_type'] && !allowable_values.include?(opts[:'document_type'])
        fail ArgumentError, "invalid value for \"document_type\", must be one of #{allowable_values}"
      end
      # resource path
      local_var_path = '/api/v2/companies/{companyCode}/transactions/{transactionCode}/shipment/verify'.sub('{' + 'companyCode' + '}', CGI.escape(company_code.to_s)).sub('{' + 'transactionCode' + '}', CGI.escape(transaction_code.to_s))

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'documentType'] = opts[:'document_type'] if !opts[:'document_type'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json'])

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body]

      # return_type
      return_type = opts[:debug_return_type] || 'ShippingVerifyResult'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['BasicAuth', 'Bearer']

      new_options = opts.merge(
        :operation => :"ShippingVerificationApi.verify_shipment",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      response = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#verify_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
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
