=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.4.7.1


=end

require 'cgi'

module AvalaraSdk
  class ShippingVerificationApi
    attr_accessor :api_client

    def initialize(api_client)
      if (api_client.nil?)
        fail  ArgumentError,'api_client is nil'
      end
      api_client.set_sdk_version("2.4.7.1")
      @api_client = api_client
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

      data, status_code, headers = @api_client.call_api(:DELETE, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#deregister_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      return data, status_code, headers
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

      data, status_code, headers = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#register_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      return data, status_code, headers
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

      data, status_code, headers = @api_client.call_api(:PUT, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#register_shipment_if_compliant\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      return data, status_code, headers
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

      data, status_code, headers = @api_client.call_api(:GET, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: ShippingVerificationApi#verify_shipment\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      return data, status_code, headers
    end
  end
end
