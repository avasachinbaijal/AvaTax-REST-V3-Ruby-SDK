=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.3.1


=end

require 'cgi'

module AvalaraSdk
  class AgeVerificationApi
    attr_accessor :api_client

    def initialize(api_client)
      if (api_client.nil?)
        fail  ArgumentError,'api_client is nil'
      end
      api_client.set_sdk_version("2.3.1")
      @api_client = api_client
    end
    # Determines whether an individual meets or exceeds the minimum legal drinking age.
    # The request must meet the following criteria in order to be evaluated: * *firstName*, *lastName*, and *address* are required fields. * One of the following sets of attributes are required for the *address*:   * *line1, city, region*   * *line1, postalCode*  Optionally, the transaction and its lines may use the following parameters: * A *DOB* (Date of Birth) field. The value should be ISO-8601 compliant (e.g. 2020-07-21). * Beyond the required *address* fields above, a *country* field is permitted   * The valid values for this attribute are [*US, USA*]  **Security Policies** This API depends on the active subscription *AgeVerification*
    # @param age_verify_request [AgeVerifyRequest] Information about the individual whose age is being verified.
    # @param [Hash] opts the optional parameters
    # @option opts [AgeVerifyFailureCode] :simulated_failure_code (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes.
    # @return [AgeVerifyResult]
    def verify_age(age_verify_request, opts = {})
      data, _status_code, _headers = verify_age_with_http_info(age_verify_request, opts)
      data
    end

    # Determines whether an individual meets or exceeds the minimum legal drinking age.
    # The request must meet the following criteria in order to be evaluated: * *firstName*, *lastName*, and *address* are required fields. * One of the following sets of attributes are required for the *address*:   * *line1, city, region*   * *line1, postalCode*  Optionally, the transaction and its lines may use the following parameters: * A *DOB* (Date of Birth) field. The value should be ISO-8601 compliant (e.g. 2020-07-21). * Beyond the required *address* fields above, a *country* field is permitted   * The valid values for this attribute are [*US, USA*]  **Security Policies** This API depends on the active subscription *AgeVerification*
    # @param age_verify_request [AgeVerifyRequest] Information about the individual whose age is being verified.
    # @param [Hash] opts the optional parameters
    # @option opts [AgeVerifyFailureCode] :simulated_failure_code (Optional) The failure code included in the simulated response of the endpoint. Note that this endpoint is only available in Sandbox for testing purposes.
    # @return [Array<(AgeVerifyResult, Integer, Hash)>] AgeVerifyResult data, response status code and response headers
    def verify_age_with_http_info(age_verify_request, opts = {})
      if @api_client.config.debugging
        @api_client.config.logger.debug 'Calling API: AgeVerificationApi.verify_age ...'
      end
      # verify the required parameter 'age_verify_request' is set
      if @api_client.config.client_side_validation && age_verify_request.nil?
        fail ArgumentError, "Missing the required parameter 'age_verify_request' when calling AgeVerificationApi.verify_age"
      end
      # resource path
      local_var_path = '/api/v2/ageverification/verify'

      # query parameters
      query_params = opts[:query_params] || {}
      query_params[:'simulatedFailureCode'] = opts[:'simulated_failure_code'] if !opts[:'simulated_failure_code'].nil?

      # header parameters
      header_params = opts[:header_params] || {}
      # HTTP header 'Accept' (if needed)
      header_params['Accept'] = @api_client.select_header_accept(['application/json'])
      # HTTP header 'Content-Type'
      content_type = @api_client.select_header_content_type(['application/json'])
      if !content_type.nil?
          header_params['Content-Type'] = content_type
      end

      # form parameters
      form_params = opts[:form_params] || {}

      # http body (model)
      post_body = opts[:debug_body] || @api_client.object_to_http_body(age_verify_request)

      # return_type
      return_type = opts[:debug_return_type] || 'AgeVerifyResult'

      # auth_names
      auth_names = opts[:debug_auth_names] || ['BasicAuth', 'Bearer']

      new_options = opts.merge(
        :operation => :"AgeVerificationApi.verify_age",
        :header_params => header_params,
        :query_params => query_params,
        :form_params => form_params,
        :body => post_body,
        :auth_names => auth_names,
        :return_type => return_type
      )

      data, status_code, headers = @api_client.call_api(:POST, local_var_path, new_options)
      if @api_client.config.debugging
        @api_client.config.logger.debug "API called: AgeVerificationApi#verify_age\nData: #{data.inspect}\nStatus code: #{status_code}\nHeaders: #{headers}"
      end
      return data, status_code, headers
    end
  end
end
