module AvalaraSdk
  class TokenMetadata
    attr_accessor :access_token
    attr_accessor :expiry

    def initialize(access_token, expiry_time)
      @access_token = access_token
      @expiry = expiry_time
    end
  end
end